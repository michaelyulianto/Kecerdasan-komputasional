"""Prototipe Streamlit: Prioritisasi Kerentanan Server berbasis Certainty Factor.

Jalankan:  streamlit run app.py
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

from cf_engine import (CF_THRESHOLD, CONFIDENCE_TERMS, HYPOTHESIS, KEPENTINGAN, KETERPAPARAN, RULES, TERM_SCALE,
                       _fmt, evaluate)
from fetch_scores import is_real_cve
from pipeline import COLUMNS, epss_two_dates, evaluate_frame, fill_scores, normalize_frame, ranking_table

HERE = Path(__file__).parent
st.set_page_config(page_title="Prioritas Kerentanan CF", page_icon="🛡️", layout="wide")

TERMS = list(CONFIDENCE_TERMS.keys())
# Kasus contoh = Tabel IV pada paper (nilai ilustratif, bukan CVE asli)
EXAMPLES = pd.DataFrame([
    ["A", "srv-web-01", "CVE-ILUSTRASI-A", 9.8, 0.94, "Tinggi", "Pasti", "Open", "Pasti"],
    ["B", "srv-dev-02", "CVE-ILUSTRASI-B", 5.3, 0.004, "Rendah", "Pasti", "Small", "Pasti"],
    ["C", "srv-app-03", "CVE-ILUSTRASI-C", 9.8, 0.004, "Sedang", "Pasti", "Open", "Kemungkinan besar"],
], columns=["ID", "Server", "CVE", "CVSS", "EPSS", "Kepentingan", "Keyakinan kepentingan",
            "Keterpaparan", "Keyakinan keterpaparan"])
MANUAL = {"A": 0.9808, "B": -0.784, "C": 0.573333}  # hasil manual pada paper (Bagian III.C)


def set_data(df: pd.DataFrame):
    st.session_state.data = normalize_frame(df)
    st.session_state.pop("editor", None)


if "data" not in st.session_state:
    set_data(pd.read_csv(HERE / "skenario_contoh.csv"))

# ======================= UI =======================
st.title("🛡️ Prioritisasi Kerentanan Server — Certainty Factor")
st.caption(f"Hipotesis H: “{HYPOTHESIS}.” Nilai CF akhir adalah skor dukungan berbasis aturan, "
           "**bukan** probabilitas eksploitasi (probabilitas tetap dari EPSS).")

tab_input, tab_hasil, tab_rinci, tab_epss, tab_aturan, tab_verif = st.tabs(
    ["📥 Data Masukan", "📊 Hasil Prioritas", "🔍 Rincian Perhitungan", "📅 EPSS Dua Tanggal",
     "📚 Basis Aturan", "✅ Verifikasi Manual"])

# ---------- Tab: input ----------
with tab_input:
    st.markdown("#### Langkah 1 — Siapkan skenario pasangan CVE–server")
    st.write("Skenario berisi kode CVE **asli** dan kondisi server **simulasi** (kepentingan & keterpaparan). "
             "Kolom CVSS dan EPSS boleh kosong karena diisi pada Langkah 2.")
    c1, c2, c3 = st.columns(3)
    c1.download_button("⬇️ Unduh template skenario (CSV)", (HERE / "skenario_contoh.csv").read_bytes(),
                       file_name="skenario_contoh.csv", mime="text/csv")
    if c2.button("Pakai skenario contoh (CVE asli)"):
        set_data(pd.read_csv(HERE / "skenario_contoh.csv"))
        st.rerun()
    if c3.button("Pakai contoh ilustrasi paper (Kasus A, B, C)"):
        set_data(EXAMPLES)
        st.rerun()
    up = st.file_uploader("Atau unggah CSV skenario kalian (kolom wajib: ID, Server, CVE, Kepentingan, "
                          "Keyakinan kepentingan, Keterpaparan, Keyakinan keterpaparan)", type="csv")
    if up is not None and st.button("Muat CSV"):
        try:
            set_data(pd.read_csv(up))
            st.rerun()
        except ValueError as e:
            st.error(str(e))

    st.markdown("#### Langkah 2 — Ambil skor asli dari NVD (CVSS v3.1) dan FIRST (EPSS)")
    st.write("Skor diambil untuk semua baris yang kodenya berformat CVE asli. CVE tanpa CVSS v3.1 atau tanpa "
             "EPSS ditandai dan dikeluarkan (batasan paper). Tanggal skor dan tanggal pengambilan ikut dicatat.")
    d1, d2 = st.columns(2)
    use_date = d1.checkbox("Gunakan EPSS dari tanggal tertentu (default: skor terbaru)")
    epss_date = d1.date_input("Tanggal EPSS", value=date.today() - timedelta(days=1),
                              max_value=date.today(), disabled=not use_date)
    api_key = d2.text_input("API key NVD (opsional — tanpa key, jeda ±6 detik per CVE)", type="password")
    n_cve = len({str(c).strip().upper() for c in st.session_state.data["CVE"] if is_real_cve(c)})
    if st.button(f"🌐 Ambil CVSS & EPSS untuk semua baris (±{n_cve * (1 if api_key else 6)} detik)", type="primary"):
        bar = st.progress(0.0, text="Mengambil EPSS dari FIRST…")

        def progress(i, n, cve):
            bar.progress(i / max(n, 1), text=f"Mengambil CVSS dari NVD: {cve} ({i + 1}/{n})")

        try:
            df_new, log = fill_scores(st.session_state.data, str(epss_date) if use_date else None,
                                      api_key or None, progress)
            bar.empty()
            set_data(df_new)
            st.session_state.fetch_log = log
            st.rerun()
        except Exception as e:
            bar.empty()
            st.error(f"Gagal menghubungi NVD/FIRST: {e}")
    for line in st.session_state.get("fetch_log", []):
        st.info(line)

    st.markdown("#### Langkah 3 — Periksa / edit data")
    st.write("Tabel bisa diedit langsung (➕ di bawah tabel untuk menambah baris). Kolom keyakinan = CF(E) kondisi "
             "server (Tabel II); “Tidak tahu” tidak mengaktifkan aturan (ambang 0,2).")
    edited = st.data_editor(
        st.session_state.data, num_rows="dynamic", width="stretch", key="editor",
        column_config={
            "CVSS": st.column_config.NumberColumn("CVSS v3.1", min_value=0.0, max_value=10.0, step=0.1, format="%.1f"),
            "EPSS": st.column_config.NumberColumn("EPSS", min_value=0.0, max_value=1.0, format="%.5f"),
            "Kepentingan": st.column_config.SelectboxColumn(options=KEPENTINGAN, required=True, default="Sedang"),
            "Keyakinan kepentingan": st.column_config.SelectboxColumn(options=TERMS, required=True, default="Pasti"),
            "Keterpaparan": st.column_config.SelectboxColumn(options=KETERPAPARAN, required=True, default="Controlled"),
            "Keyakinan keterpaparan": st.column_config.SelectboxColumn(options=TERMS, required=True, default="Pasti"),
        },
    )
    st.session_state.current = edited
    st.download_button("⬇️ Simpan snapshot data bertanggal (CSV)", edited.to_csv(index=False).encode("utf-8"),
                       file_name=f"snapshot_data_{date.today()}.csv", mime="text/csv",
                       help="Simpan file ini sebagai data uji resmi supaya pengujian bisa diulang (Bab IV.A).")

current = st.session_state.get("current", st.session_state.data)
results, errors = evaluate_frame(current)
if errors:
    with st.sidebar:
        st.markdown("**Baris yang dilewati**")
        for e in errors:
            st.warning(e)

# ---------- Tab: hasil ----------
with tab_hasil:
    table = ranking_table(results)
    if table.empty:
        st.info("Belum ada data valid. Isi CVSS & EPSS dulu di tab Data Masukan (Langkah 2).")
    else:
        m1, m2, m3 = st.columns(3)
        m1.metric("Pasangan CVE–server", len(table))
        m2.metric("CF > 0 (mendukung)", int((table["CF akhir"] > 0).sum()))
        m3.metric("CF < 0 (melemahkan)", int((table["CF akhir"] < 0).sum()))
        st.dataframe(
            table[["Urutan CF", "ID", "Server", "CVE", "CF akhir", "Interpretasi", "Aturan aktif",
                   "CVSS", "Urutan CVSS", "EPSS", "Urutan EPSS"]],
            width="stretch", hide_index=True,
            column_config={"CF akhir": st.column_config.NumberColumn(format="%.4f"),
                           "EPSS": st.column_config.NumberColumn(format="%.5f")},
        )
        st.caption("Peringkat seri berbagi nomor yang sama (1, 1, 3). Kasus dengan CF sama adalah prioritas setara.")

        st.subheader("Perbedaan urutan terhadap pembanding")
        diff_rows = []
        for _, r in table.iterrows():
            notes = []
            if r["Urutan CF"] != r["Urutan CVSS"]:
                notes.append(f"CVSS saja: #{r['Urutan CVSS']} → CF: #{r['Urutan CF']}")
            if r["Urutan CF"] != r["Urutan EPSS"]:
                notes.append(f"EPSS saja: #{r['Urutan EPSS']} → CF: #{r['Urutan CF']}")
            diff_rows.append({"ID": r["ID"], "CVE": r["CVE"], "Server": r["Server"],
                              "Perubahan": "; ".join(notes) or "Posisi sama",
                              "Dijelaskan oleh aturan": r["Aturan aktif"]})
        st.dataframe(pd.DataFrame(diff_rows), width="stretch", hide_index=True)

        out = table.copy()
        out["Tanggal proses"] = str(date.today())
        st.download_button("⬇️ Unduh hasil prioritas (CSV)", out.to_csv(index=False).encode("utf-8"),
                           file_name=f"hasil_prioritas_{date.today()}.csv", mime="text/csv")

# ---------- Tab: rincian ----------
with tab_rinci:
    if not results:
        st.info("Belum ada data valid.")
    else:
        labels = {f"{r.case_id} — {row['CVE']} @ {row['Server']}": (row, r) for row, r in results}
        row, res = labels[st.selectbox("Pilih kasus", list(labels))]
        for w in res.warnings:
            st.warning(w)

        st.markdown("**1. Penilaian evidence (Tabel I)**")
        st.dataframe(pd.DataFrame([{"Evidence": e.name, "Nilai masukan": e.raw, "Kategori": e.category,
                                    "CF(E)": _fmt(e.cf_e), "Keterangan": e.note} for e in res.evidences]),
                     width="stretch", hide_index=True)

        st.markdown("**2. Aturan aktif — CF(H,E) = CF(E) × CF(Rule)**")
        if res.fired:
            st.dataframe(pd.DataFrame([{
                "Aturan": f.rule.code, "Bunyi": f.rule.text, "CF(E)": _fmt(f.cf_e),
                "CF(Rule)": f"{_fmt(f.rule.cf)} ({f.rule.term})",
                "CF(H,E)": f"{_fmt(f.cf_e)} × {_fmt(f.rule.cf)} = {_fmt(f.cf_he)}"} for f in res.fired]),
                width="stretch", hide_index=True)
        for rule, why in res.not_fired:
            st.caption(f"{rule.code} premis cocok tetapi tidak aktif: {why}")

        st.markdown("**3. Kombinasi (fungsi EMYCIN)**")
        eq_name = {1: "(1) keduanya ≥ 0", 2: "(2) keduanya < 0", 3: "(3) tanda berbeda"}
        if res.steps:
            for i, s in enumerate(res.steps, 1):
                st.code(f"Langkah {i}: gabung dengan {s.rule_code}  — persamaan {eq_name[s.equation]}\n"
                        f"CFcomb = {s.formula}", language=None)
        elif res.fired:
            st.write("Hanya satu aturan aktif, tidak perlu kombinasi.")
        st.success(f"CF akhir = {res.cf_final:.6f}")

# ---------- Tab: EPSS dua tanggal ----------
with tab_epss:
    st.write("Analisis tambahan (Bab IV.B): EPSS diambil dari **dua tanggal berbeda**, sedangkan CVSS, kondisi "
             "server, dan aturan tetap sama. Perubahan urutan karenanya dapat dikaitkan dengan perubahan EPSS. "
             "Nilai EPSS kedua tanggal tidak digabungkan.")
    e1, e2 = st.columns(2)
    date1 = e1.date_input("Tanggal 1", value=date.today() - timedelta(days=90), max_value=date.today())
    date2 = e2.date_input("Tanggal 2", value=date.today() - timedelta(days=1), max_value=date.today())
    if st.button("🌐 Bandingkan EPSS dua tanggal"):
        try:
            with st.spinner("Mengambil EPSS historis dari FIRST…"):
                st.session_state.two_dates = epss_two_dates(current, str(date1), str(date2))
        except Exception as e:
            st.error(f"Gagal menghubungi FIRST: {e}")
    if "two_dates" in st.session_state:
        t, log = st.session_state.two_dates
        for line in log:
            st.warning(line)
        if not t.empty:
            st.dataframe(t, width="stretch", hide_index=True)
            st.caption("Perubahan posisi positif = naik peringkat pada tanggal 2. "
                       "“R5 → R4” berarti EPSS melewati ambang 0,1.")
            st.download_button("⬇️ Unduh analisis dua tanggal (CSV)", t.to_csv(index=False).encode("utf-8"),
                               file_name="analisis_epss_dua_tanggal.csv", mime="text/csv")

# ---------- Tab: basis aturan ----------
with tab_aturan:
    st.markdown(f"Ambang premis EMYCIN: aturan aktif hanya jika **CF(E) > {_fmt(CF_THRESHOLD)}**. "
                "Satu premis per aturan sehingga satu evidence tidak dihitung dua kali.")
    a1, a2 = st.columns([3, 2])
    with a1:
        st.markdown("**Tabel I — Kategori penilaian evidence**")
        st.dataframe(pd.DataFrame([
            ["CVSS v3.1 Base", "Critical / High / Medium / Low", "9,0–10,0 / 7,0–8,9 / 4,0–6,9 / 0,1–3,9", "Skala keparahan CVSS v3.1"],
            ["EPSS (30 hari)", "Tinggi / Rendah", "≥ 0,1 / < 0,1", "Ambang 10% yang dicontohkan FIRST"],
            ["Kepentingan server", "Tinggi / Sedang / Rendah", "Dampak C/I/A katastrofik / serius / terbatas", "Security Requirements CVSS v3.1"],
            ["Keterpaparan", "Open / Controlled / Small", "Internet / akses dibatasi / lokal terkendali", "System Exposure SSVC"],
        ], columns=["Masukan", "Kategori", "Kriteria", "Sumber"]), width="stretch", hide_index=True)
        st.markdown("**Tabel III — Basis aturan**")
        st.dataframe(pd.DataFrame([{"Kode": r.code, "Aturan": r.text, "CF(Rule)": _fmt(r.cf), "Istilah": r.term}
                                   for r in RULES]), width="stretch", hide_index=True)
        st.caption("CVSS Medium, kepentingan Sedang, dan keterpaparan Controlled bersifat netral (tidak ada aturan).")
    with a2:
        st.markdown("**Tabel II — Skala istilah CF (Sutojo dkk., 2011)**")
        st.dataframe(pd.DataFrame([{"Istilah": t, "CF": "−0,2 s.d. 0,2" if t == "Tidak tahu" else _fmt(v)}
                                   for t, v in TERM_SCALE]), width="stretch", hide_index=True)

# ---------- Tab: verifikasi ----------
with tab_verif:
    st.write("Membandingkan hasil sistem dengan perhitungan manual pada paper (Bagian III.C). "
             "Kriteria: selisih absolut ≤ 1 × 10⁻⁶.")
    rows = []
    for _, ex in EXAMPLES.iterrows():
        r = evaluate(ex["ID"], ex["CVSS"], ex["EPSS"], ex["Kepentingan"], ex["Keyakinan kepentingan"],
                     ex["Keterpaparan"], ex["Keyakinan keterpaparan"])
        diff = abs(r.cf_final - MANUAL[ex["ID"]])
        rows.append({"Kasus": ex["ID"], "Manual (paper)": MANUAL[ex["ID"]], "Sistem": round(r.cf_final, 6),
                     "Selisih": f"{diff:.1e}", "Status": "✅ Sesuai" if diff <= 1e-6 else "❌ Tidak sesuai"})
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.caption("Nilai manual Kasus C ditulis 0,5733 di paper (dibulatkan); nilai tepatnya 0,573333…")

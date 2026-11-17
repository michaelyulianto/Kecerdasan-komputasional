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
from pipeline import epss_two_dates, evaluate_frame, fill_scores, normalize_frame, ranking_table

HERE = Path(__file__).parent
st.set_page_config(page_title="Prioritisasi Kerentanan Server — CF", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 2.2rem; max-width: 1280px;}
.app-header {border-left: 5px solid #1F4E79; padding: 0.2rem 0 0.2rem 1rem; margin-bottom: 1.2rem;}
.app-header h1 {font-size: 1.9rem; margin: 0; padding: 0; color: #1B2430;}
.app-header p {margin: 0.35rem 0 0 0; color: #4A5565; font-size: 0.95rem;}
.step-label {font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
             color: #1F4E79; margin-bottom: 0.1rem;}
.note {color: #4A5565; font-size: 0.9rem;}
div[data-testid="stMetricValue"] {font-size: 1.6rem;}
button[data-baseweb="tab"] p {font-size: 0.95rem; font-weight: 600;}
</style>
""", unsafe_allow_html=True)

TERMS = list(CONFIDENCE_TERMS.keys())
# Kasus contoh = Tabel IV pada paper (nilai ilustratif, bukan CVE asli)
EXAMPLES = pd.DataFrame([
    ["A", "srv-web-01", "CVE-ILUSTRASI-A", 9.8, 0.94, "Tinggi", "Pasti", "Open", "Pasti"],
    ["B", "srv-dev-02", "CVE-ILUSTRASI-B", 5.3, 0.004, "Rendah", "Pasti", "Small", "Pasti"],
    ["C", "srv-app-03", "CVE-ILUSTRASI-C", 9.8, 0.004, "Sedang", "Pasti", "Open", "Kemungkinan besar"],
], columns=["ID", "Server", "CVE", "CVSS", "EPSS", "Kepentingan", "Keyakinan kepentingan",
            "Keterpaparan", "Keyakinan keterpaparan"])
MANUAL = {"A": 0.9808, "B": -0.784, "C": 0.573333}  # hasil manual pada paper (Bagian III.C)
EQ_NAME = {1: "(1) keduanya positif", 2: "(2) keduanya negatif", 3: "(3) tanda berbeda"}


def set_data(df: pd.DataFrame):
    st.session_state.data = normalize_frame(df)
    st.session_state.pop("editor", None)
    st.session_state.pop("two_dates", None)


def step(label: str, title: str, text: str | None = None):
    st.markdown(f'<div class="step-label">{label}</div>', unsafe_allow_html=True)
    st.markdown(f"**{title}**")
    if text:
        st.markdown(f'<div class="note">{text}</div>', unsafe_allow_html=True)


if "data" not in st.session_state:
    set_data(pd.read_csv(HERE / "skenario_contoh.csv"))

# ======================= HEADER =======================
st.markdown(f"""
<div class="app-header">
  <h1>Prioritisasi Kerentanan Server</h1>
  <p>Certainty Factor berbasis CVSS, EPSS, dan kondisi server &nbsp;·&nbsp; Kelompok 6, Kecerdasan Komputasional</p>
  <p>Hipotesis H: <i>{HYPOTHESIS}</i>. Skor CF adalah tingkat dukungan aturan, bukan probabilitas eksploitasi.</p>
</div>
""", unsafe_allow_html=True)

tab_input, tab_hasil, tab_rinci, tab_epss, tab_aturan, tab_verif = st.tabs(
    ["Data Masukan", "Hasil Prioritas", "Rincian Perhitungan", "Analisis EPSS Dua Tanggal",
     "Basis Aturan", "Verifikasi Manual"])

# ---------- Tab: input ----------
with tab_input:
    with st.container(border=True):
        step("Langkah 1", "Siapkan skenario pasangan CVE–server",
             "Skenario berisi kode CVE asli dan kondisi server simulasi (kepentingan dan keterpaparan). "
             "Kolom CVSS dan EPSS boleh kosong karena diisi otomatis pada Langkah 2.")
        c1, c2, c3 = st.columns(3)
        if c1.button("Muat skenario contoh (CVE asli)", width="stretch"):
            set_data(pd.read_csv(HERE / "skenario_contoh.csv"))
            st.rerun()
        if c2.button("Muat ilustrasi paper (Kasus A–C)", width="stretch"):
            set_data(EXAMPLES)
            st.rerun()
        c3.download_button("Unduh template skenario (CSV)", (HERE / "skenario_contoh.csv").read_bytes(),
                           file_name="skenario_contoh.csv", mime="text/csv", width="stretch")
        up = st.file_uploader("Unggah skenario sendiri. Kolom wajib: ID, Server, CVE, Kepentingan, "
                              "Keyakinan kepentingan, Keterpaparan, Keyakinan keterpaparan.", type="csv")
        if up is not None and st.button("Muat file yang diunggah"):
            try:
                set_data(pd.read_csv(up))
                st.rerun()
            except ValueError as e:
                st.error(str(e))

    with st.container(border=True):
        step("Langkah 2", "Ambil skor asli dari NVD (CVSS v3.1) dan FIRST (EPSS)",
             "Diambil untuk setiap baris berkode CVE asli. CVE tanpa CVSS v3.1 atau tanpa EPSS ditandai di kolom "
             "Catatan dan tidak dihitung. Tanggal skor dan tanggal pengambilan dicatat.")
        d1, d2 = st.columns(2)
        use_date = d1.checkbox("Gunakan EPSS dari tanggal tertentu (bawaan: skor terbaru)")
        epss_date = d1.date_input("Tanggal EPSS", value=date.today() - timedelta(days=1),
                                  max_value=date.today(), disabled=not use_date)
        api_key = d2.text_input("API key NVD (opsional)", type="password",
                                help="Tanpa API key, NVD membatasi 5 permintaan per 30 detik sehingga ada jeda "
                                     "sekitar 6 detik per CVE.")
        n_cve = len({str(c).strip().upper() for c in st.session_state.data["CVE"] if is_real_cve(c)})
        est = n_cve * (1 if api_key else 6)
        if st.button(f"Ambil CVSS dan EPSS untuk {n_cve} CVE (perkiraan {est} detik)", type="primary"):
            bar = st.progress(0.0, text="Mengambil EPSS dari FIRST")

            def progress(i, n, cve):
                bar.progress(i / max(n, 1), text=f"Mengambil CVSS dari NVD: {cve} ({i + 1} dari {n})")

            try:
                df_new, log = fill_scores(st.session_state.data, str(epss_date) if use_date else None,
                                          api_key or None, progress)
                bar.empty()
                set_data(df_new)
                st.session_state.fetch_log = log
                st.rerun()
            except Exception as e:
                bar.empty()
                st.error(f"Gagal menghubungi NVD atau FIRST: {e}")
        log = st.session_state.get("fetch_log", [])
        if log:
            st.success(log[0])
            for line in log[1:]:
                st.warning(line)

    with st.container(border=True):
        step("Langkah 3", "Periksa data, lalu simpan snapshot",
             "Tabel dapat diedit langsung; tambah baris lewat baris kosong di bawah tabel. Kolom keyakinan adalah "
             "CF(E) kondisi server (Tabel II); pilihan “Tidak tahu” tidak mengaktifkan aturan karena di bawah "
             "ambang 0,2. Simpan snapshot sebagai data uji resmi agar pengujian dapat diulang.")
        edited = st.data_editor(
            st.session_state.data, num_rows="dynamic", width="stretch", key="editor", hide_index=True,
            column_config={
                "CVSS": st.column_config.NumberColumn("CVSS v3.1", min_value=0.0, max_value=10.0, step=0.1,
                                                      format="%.1f"),
                "EPSS": st.column_config.NumberColumn("EPSS", min_value=0.0, max_value=1.0, format="%.5f"),
                "Kepentingan": st.column_config.SelectboxColumn(options=KEPENTINGAN, required=True, default="Sedang"),
                "Keyakinan kepentingan": st.column_config.SelectboxColumn(options=TERMS, required=True,
                                                                          default="Pasti"),
                "Keterpaparan": st.column_config.SelectboxColumn(options=KETERPAPARAN, required=True,
                                                                 default="Controlled"),
                "Keyakinan keterpaparan": st.column_config.SelectboxColumn(options=TERMS, required=True,
                                                                           default="Pasti"),
                "Catatan": st.column_config.TextColumn(width="large"),
            },
        )
        st.session_state.current = edited
        st.download_button("Simpan snapshot data bertanggal (CSV)", edited.to_csv(index=False).encode("utf-8"),
                           file_name=f"snapshot_data_{date.today()}.csv", mime="text/csv")

current = st.session_state.get("current", st.session_state.data)
results, errors = evaluate_frame(current)

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("### Ringkasan data")
    s1, s2 = st.columns(2)
    s1.metric("Baris", len(current))
    s2.metric("Dihitung", len(results))
    dates = sorted({d for d in current["Tanggal EPSS"] if isinstance(d, str) and d})
    st.markdown(f"**Tanggal skor EPSS:** {', '.join(dates) if dates else 'belum diambil'}")
    versions = sorted({v for v in current["Versi EPSS"] if isinstance(v, str) and v})
    if versions:
        st.markdown(f"**Model EPSS:** {', '.join(versions)}")
    if errors:
        with st.expander(f"{len(errors)} baris tidak dihitung"):
            for e in errors:
                st.markdown(f"- {e}")
    st.divider()
    st.markdown("**Sumber data**")
    st.markdown("- CVSS v3.1: NVD CVE API 2.0\n- EPSS: FIRST EPSS API\n- Kondisi server: skenario simulasi")
    st.markdown('<div class="note">Skor CF menyatakan dukungan aturan terhadap prioritas tinggi, '
                'bukan peluang eksploitasi.</div>', unsafe_allow_html=True)

# ---------- Tab: hasil ----------
with tab_hasil:
    table = ranking_table(results)
    if table.empty:
        st.info("Belum ada data yang dapat dihitung. Isi CVSS dan EPSS pada tab Data Masukan, Langkah 2.")
    else:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Pasangan dihitung", len(table))
        m2.metric("Mendukung prioritas (CF > 0)", int((table["CF akhir"] > 0).sum()))
        m3.metric("Melemahkan prioritas (CF < 0)", int((table["CF akhir"] < 0).sum()))
        top = table.iloc[0]
        m4.metric(f"Prioritas pertama (CF {top['CF akhir']:.4f})", f"{top['ID']} · {top['CVE']}")

        st.markdown("#### Urutan prioritas")
        st.dataframe(
            table[["Urutan CF", "ID", "Server", "CVE", "CF akhir", "Interpretasi", "Aturan aktif",
                   "CVSS", "Urutan CVSS", "EPSS", "Urutan EPSS"]],
            width="stretch", hide_index=True,
            column_config={
                "Urutan CF": st.column_config.NumberColumn("Urutan", width="small"),
                "CF akhir": st.column_config.ProgressColumn("CF akhir", min_value=-1.0, max_value=1.0,
                                                            format="%.4f"),
                "EPSS": st.column_config.NumberColumn(format="%.5f"),
            },
        )
        st.caption("Bilah CF berskala −1 sampai 1. Nilai seri berbagi nomor urut (1, 1, 3) dan berarti prioritas "
                   "setara. Kolom Urutan CVSS dan Urutan EPSS adalah urutan bila memakai satu skor saja.")

        st.markdown("#### Perbedaan terhadap pengurutan satu skor")
        diff_rows = []
        for _, r in table.iterrows():
            diff_rows.append({
                "ID": r["ID"], "CVE": r["CVE"], "Server": r["Server"],
                "Urutan CF": r["Urutan CF"],
                "Dibanding CVSS saja": "sama" if r["Urutan CF"] == r["Urutan CVSS"]
                else f"#{r['Urutan CVSS']} menjadi #{r['Urutan CF']}",
                "Dibanding EPSS saja": "sama" if r["Urutan CF"] == r["Urutan EPSS"]
                else f"#{r['Urutan EPSS']} menjadi #{r['Urutan CF']}",
                "Aturan yang menjelaskan": r["Aturan aktif"]})
        st.dataframe(pd.DataFrame(diff_rows), width="stretch", hide_index=True)

        out = table.copy()
        out["Tanggal proses"] = str(date.today())
        st.download_button("Unduh hasil prioritas (CSV)", out.to_csv(index=False).encode("utf-8"),
                           file_name=f"hasil_prioritas_{date.today()}.csv", mime="text/csv")

# ---------- Tab: rincian ----------
with tab_rinci:
    if not results:
        st.info("Belum ada data yang dapat dihitung.")
    else:
        labels = {f"{r.case_id}  ·  {row['CVE']}  ·  {row['Server']}": (row, r) for row, r in results}
        row, res = labels[st.selectbox("Pilih pasangan CVE–server", list(labels))]
        for w in res.warnings:
            st.warning(w)

        k1, k2, k3 = st.columns(3)
        k1.metric("CF akhir", f"{res.cf_final:.6f}")
        k2.metric("Aturan aktif", len(res.fired))
        k3.metric("Langkah kombinasi", len(res.steps))

        with st.container(border=True):
            step("Tahap 1", "Penilaian evidence (Tabel I)")
            st.dataframe(pd.DataFrame([{"Evidence": e.name, "Nilai masukan": e.raw, "Kategori": e.category,
                                        "CF(E)": _fmt(e.cf_e), "Keterangan": e.note} for e in res.evidences]),
                         width="stretch", hide_index=True)

        with st.container(border=True):
            step("Tahap 2", "Aturan aktif: CF(H,E) = CF(E) × CF(Rule)")
            if res.fired:
                st.dataframe(pd.DataFrame([{
                    "Aturan": f.rule.code, "Bunyi aturan": f.rule.text, "CF(E)": _fmt(f.cf_e),
                    "CF(Rule)": f"{_fmt(f.rule.cf)} ({f.rule.term})",
                    "CF(H,E)": f"{_fmt(f.cf_e)} × {_fmt(f.rule.cf)} = {_fmt(f.cf_he)}"} for f in res.fired]),
                    width="stretch", hide_index=True)
            else:
                st.write("Tidak ada aturan aktif.")
            for rule, why in res.not_fired:
                st.caption(f"{rule.code} premisnya cocok tetapi tidak aktif: {why}.")

        with st.container(border=True):
            step("Tahap 3", "Kombinasi dengan fungsi EMYCIN")
            if res.steps:
                st.dataframe(pd.DataFrame([{
                    "Langkah": i, "Digabung dengan": s.rule_code, "Persamaan": EQ_NAME[s.equation],
                    "Perhitungan": s.formula} for i, s in enumerate(res.steps, 1)]),
                    width="stretch", hide_index=True)
            elif res.fired:
                st.write("Hanya satu aturan aktif sehingga tidak diperlukan kombinasi.")
            st.markdown(f"**CF akhir = {res.cf_final:.6f}**")

# ---------- Tab: EPSS dua tanggal ----------
with tab_epss:
    st.markdown("Analisis tambahan sesuai Bab IV.B. EPSS diambil dari dua tanggal, sedangkan CVSS, kondisi "
                "server, dan aturan tetap sama, sehingga perubahan urutan dapat dikaitkan dengan perubahan EPSS. "
                "Nilai EPSS kedua tanggal tidak digabungkan.")
    with st.container(border=True):
        e1, e2, e3 = st.columns([2, 2, 1.4])
        date1 = e1.date_input("Tanggal pertama", value=date.today() - timedelta(days=90), max_value=date.today())
        date2 = e2.date_input("Tanggal kedua", value=date.today() - timedelta(days=1), max_value=date.today())
        e3.markdown("<div style='height:1.75rem'></div>", unsafe_allow_html=True)
        run = e3.button("Bandingkan", type="primary", width="stretch")
    if run:
        try:
            with st.spinner("Mengambil EPSS historis dari FIRST"):
                st.session_state.two_dates = epss_two_dates(current, str(date1), str(date2))
        except Exception as e:
            st.error(f"Gagal menghubungi FIRST: {e}")
    if "two_dates" in st.session_state:
        t, log = st.session_state.two_dates
        for line in log:
            st.warning(line)
        if not t.empty:
            moved = int((t["Perubahan posisi"] != 0).sum())
            crossed = int(t["Aturan EPSS"].str.contains("→").sum())
            n1, n2, n3 = st.columns(3)
            n1.metric("Pasangan dibandingkan", len(t))
            n2.metric("Berubah posisi", moved)
            n3.metric("Melewati ambang 0,1", crossed)
            fmt = {c: st.column_config.NumberColumn(format="%.5f") for c in t.columns if c.startswith("EPSS ")}
            fmt.update({c: st.column_config.NumberColumn(format="%.4f") for c in t.columns if c.startswith("CF ")})
            st.dataframe(t, width="stretch", hide_index=True, column_config=fmt)
            st.caption("CF hanya berubah jika EPSS berpindah kategori (melewati ambang 0,1), karena aturan membaca "
                       "kategori, bukan angka mentah. Perubahan EPSS di dalam kategori yang sama tidak mengubah CF.")
            st.caption("Perubahan posisi positif berarti naik peringkat pada tanggal kedua. "
                       "“R5 → R4” berarti EPSS naik melewati ambang 0,1; “R4 → R5” sebaliknya.")
            st.download_button("Unduh analisis dua tanggal (CSV)", t.to_csv(index=False).encode("utf-8"),
                               file_name="analisis_epss_dua_tanggal.csv", mime="text/csv")

# ---------- Tab: basis aturan ----------
with tab_aturan:
    st.markdown(f"Aturan aktif hanya jika premisnya cocok dan CF(E) lebih besar dari {_fmt(CF_THRESHOLD)} "
                "(ambang EMYCIN). Setiap aturan memiliki satu premis sehingga satu evidence tidak dihitung dua kali.")
    with st.container(border=True):
        step("Tabel I", "Kategori penilaian evidence")
        st.dataframe(pd.DataFrame([
            ["CVSS v3.1 Base", "Critical / High / Medium / Low", "9,0–10,0 / 7,0–8,9 / 4,0–6,9 / 0,1–3,9",
             "Skala keparahan CVSS v3.1"],
            ["EPSS (30 hari)", "Tinggi / Rendah", "≥ 0,1 / < 0,1", "Ambang 10% yang dicontohkan FIRST"],
            ["Kepentingan server", "Tinggi / Sedang / Rendah", "Dampak C/I/A katastrofik / serius / terbatas",
             "Security Requirements CVSS v3.1"],
            ["Keterpaparan", "Open / Controlled / Small", "Internet / akses dibatasi / lokal terkendali",
             "System Exposure SSVC"],
        ], columns=["Masukan", "Kategori", "Kriteria", "Sumber"]), width="stretch", hide_index=True)
    a1, a2 = st.columns([3, 2])
    with a1:
        with st.container(border=True):
            step("Tabel III", "Basis aturan")
            st.dataframe(pd.DataFrame([{"Kode": r.code, "Aturan": r.text, "CF(Rule)": _fmt(r.cf), "Istilah": r.term}
                                       for r in RULES]), width="stretch", hide_index=True)
            st.caption("CVSS Medium, kepentingan Sedang, dan keterpaparan Controlled bersifat netral "
                       "sehingga tidak memiliki aturan.")
    with a2:
        with st.container(border=True):
            step("Tabel II", "Skala istilah CF (Sutojo dkk., 2011)")
            st.dataframe(pd.DataFrame([{"Istilah": t, "CF": "−0,2 s.d. 0,2" if t == "Tidak tahu" else _fmt(v)}
                                       for t, v in TERM_SCALE]), width="stretch", hide_index=True)
        with st.container(border=True):
            step("Rumus", "Fungsi kombinasi EMYCIN")
            st.markdown("1. Keduanya positif: CF₁ + CF₂(1 − CF₁)\n"
                        "2. Keduanya negatif: CF₁ + CF₂(1 + CF₁)\n"
                        "3. Tanda berbeda: (CF₁ + CF₂) / (1 − min(|CF₁|, |CF₂|))")

# ---------- Tab: verifikasi ----------
with tab_verif:
    st.markdown("Hasil sistem dibandingkan dengan perhitungan manual pada paper (Bagian III.C). "
                "Kriteria kesesuaian: selisih absolut tidak lebih dari 1 × 10⁻⁶.")
    rows = []
    for _, ex in EXAMPLES.iterrows():
        r = evaluate(ex["ID"], ex["CVSS"], ex["EPSS"], ex["Kepentingan"], ex["Keyakinan kepentingan"],
                     ex["Keterpaparan"], ex["Keyakinan keterpaparan"])
        diff = abs(r.cf_final - MANUAL[ex["ID"]])
        rows.append({"Kasus": ex["ID"], "Hasil manual (paper)": MANUAL[ex["ID"]], "Hasil sistem": round(r.cf_final, 6),
                     "Selisih": f"{diff:.1e}", "Status": "Sesuai" if diff <= 1e-6 else "Tidak sesuai"})
    passed = sum(r["Status"] == "Sesuai" for r in rows)
    v1, v2 = st.columns(2)
    v1.metric("Kasus diuji", len(rows))
    v2.metric("Sesuai", f"{passed} dari {len(rows)}")
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.caption("Hasil manual Kasus C ditulis 0,5733 di paper (dibulatkan); nilai tepatnya 0,573333.")

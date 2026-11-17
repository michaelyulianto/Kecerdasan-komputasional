"""Prototipe Streamlit: Prioritisasi Kerentanan Server berbasis Certainty Factor.

Jalankan:  streamlit run app.py
"""
from __future__ import annotations

from datetime import date

import pandas as pd
import streamlit as st

from cf_engine import (CF_THRESHOLD, CONFIDENCE_TERMS, HYPOTHESIS, KEPENTINGAN, KETERPAPARAN, RULES, TERM_SCALE,
                       _fmt, competition_rank, evaluate)

st.set_page_config(page_title="Prioritas Kerentanan CF", page_icon="🛡️", layout="wide")

TERMS = list(CONFIDENCE_TERMS.keys())
COLUMNS = ["ID", "Server", "CVE", "CVSS", "EPSS", "Kepentingan", "Keyakinan kepentingan",
           "Keterpaparan", "Keyakinan keterpaparan", "Sumber CVSS", "Tanggal EPSS", "Versi EPSS"]

# Kasus contoh = Tabel IV pada paper (nilai ilustratif)
EXAMPLES = [
    ["A", "srv-web-01", "CVE-ILUSTRASI-A", 9.8, 0.94, "Tinggi", "Pasti", "Open", "Pasti", "Ilustrasi", "", ""],
    ["B", "srv-dev-02", "CVE-ILUSTRASI-B", 5.3, 0.004, "Rendah", "Pasti", "Small", "Pasti", "Ilustrasi", "", ""],
    ["C", "srv-app-03", "CVE-ILUSTRASI-C", 9.8, 0.004, "Sedang", "Pasti", "Open", "Kemungkinan besar", "Ilustrasi", "", ""],
]
MANUAL = {"A": 0.9808, "B": -0.784, "C": 0.573333}  # hasil manual pada paper (Bagian III.C)


def init_state():
    if "data" not in st.session_state:
        st.session_state.data = pd.DataFrame(EXAMPLES, columns=COLUMNS)


def evaluate_frame(df: pd.DataFrame):
    results, errors = [], []
    for i, row in df.iterrows():
        rid = str(row.get("ID") or f"#{i + 1}")
        try:
            if pd.isna(row["CVSS"]) or pd.isna(row["EPSS"]):
                raise ValueError("CVSS atau EPSS kosong")
            res = evaluate(rid, float(row["CVSS"]), float(row["EPSS"]), row["Kepentingan"],
                           row["Keyakinan kepentingan"], row["Keterpaparan"], row["Keyakinan keterpaparan"])
            results.append((row, res))
        except (ValueError, KeyError, TypeError) as e:
            errors.append(f"Baris {rid}: {e} — dilewati.")
    return results, errors


def ranking_table(results) -> pd.DataFrame:
    rows = [{
        "ID": r.case_id, "Server": row["Server"], "CVE": row["CVE"],
        "CVSS": float(row["CVSS"]), "EPSS": float(row["EPSS"]),
        "Aturan aktif": ", ".join(f.rule.code for f in r.fired) or "—",
        "CF akhir": r.cf_final,
    } for row, r in results]
    t = pd.DataFrame(rows)
    if t.empty:
        return t
    t["Urutan CF"] = competition_rank(t["CF akhir"].tolist())
    t["Urutan CVSS"] = competition_rank(t["CVSS"].tolist())
    t["Urutan EPSS"] = competition_rank(t["EPSS"].tolist())
    t["Interpretasi"] = t["CF akhir"].apply(
        lambda v: "Mendukung prioritas tinggi" if v > 0 else ("Melemahkan prioritas tinggi" if v < 0 else "Netral"))
    return t.sort_values(["Urutan CF", "ID"]).reset_index(drop=True)


# ======================= UI =======================
init_state()
st.title("🛡️ Prioritisasi Kerentanan Server — Certainty Factor")
st.caption(f"Hipotesis H: “{HYPOTHESIS}.” Nilai CF akhir adalah skor dukungan berbasis aturan, "
           "**bukan** probabilitas eksploitasi (probabilitas tetap dari EPSS).")

tab_input, tab_hasil, tab_rinci, tab_aturan, tab_verif = st.tabs(
    ["📥 Data Masukan", "📊 Hasil Prioritas", "🔍 Rincian Perhitungan", "📚 Basis Aturan", "✅ Verifikasi Manual"])

# ---------- Tab: input ----------
with tab_input:
    st.subheader("Pasangan CVE–server")
    st.write("Edit langsung di tabel. Tambah baris lewat ikon ➕ di bawah tabel. "
             "Kolom keyakinan = CF(E) kondisi server (Tabel II). “Tidak tahu” tidak mengaktifkan aturan (ambang 0,2).")
    edited = st.data_editor(
        st.session_state.data, num_rows="dynamic", width="stretch", key="editor",
        column_config={
            "CVSS": st.column_config.NumberColumn("CVSS v3.1", min_value=0.0, max_value=10.0, step=0.1, format="%.1f"),
            "EPSS": st.column_config.NumberColumn("EPSS", min_value=0.0, max_value=1.0, step=0.00001, format="%.5f"),
            "Kepentingan": st.column_config.SelectboxColumn(options=KEPENTINGAN, required=True, default="Sedang"),
            "Keyakinan kepentingan": st.column_config.SelectboxColumn(options=TERMS, required=True, default="Pasti"),
            "Keterpaparan": st.column_config.SelectboxColumn(options=KETERPAPARAN, required=True, default="Controlled"),
            "Keyakinan keterpaparan": st.column_config.SelectboxColumn(options=TERMS, required=True, default="Pasti"),
        },
    )
    st.session_state.current = edited  # jangan timpa data dasar editor (hindari reset edit)

    c1, c2 = st.columns(2)
    if c1.button("↺ Kembalikan ke contoh paper (Kasus A, B, C)"):
        st.session_state.data = pd.DataFrame(EXAMPLES, columns=COLUMNS)
        st.session_state.pop("editor", None)
        st.rerun()
    c2.download_button("⬇️ Unduh data masukan (CSV)", edited.to_csv(index=False).encode("utf-8"),
                       file_name="data_masukan.csv", mime="text/csv")

    up = st.file_uploader("Atau unggah CSV dengan kolom yang sama", type="csv")
    if up is not None and st.button("Muat CSV"):
        df_up = pd.read_csv(up)
        missing = [c for c in COLUMNS[:9] if c not in df_up.columns]
        if missing:
            st.error(f"Kolom hilang: {', '.join(missing)}")
        else:
            for c in COLUMNS[9:]:
                df_up[c] = df_up.get(c, "")
            st.session_state.data = df_up[COLUMNS]
            st.session_state.pop("editor", None)
            st.rerun()

    st.divider()
    st.subheader("Tambah dari NVD & FIRST")
    st.write("Mengambil **CVSS v3.1 Base Score** dari NVD dan **EPSS** dari FIRST secara otomatis. "
             "Tanggal dan versi model EPSS ikut dicatat. CVE tanpa CVSS v3.1 ditolak (sesuai batasan paper).")
    with st.form("fetch_form", clear_on_submit=False):
        f1, f2, f3 = st.columns(3)
        cve_in = f1.text_input("Kode CVE", placeholder="CVE-2021-44228")
        server_in = f2.text_input("Nama server", placeholder="srv-web-01")
        id_in = f3.text_input("ID kasus", placeholder="K1")
        g1, g2, g3, g4 = st.columns(4)
        kep = g1.selectbox("Kepentingan", KEPENTINGAN)
        kep_t = g2.selectbox("Keyakinan kepentingan", TERMS)
        exp = g3.selectbox("Keterpaparan", KETERPAPARAN)
        exp_t = g4.selectbox("Keyakinan keterpaparan", TERMS)
        submitted = st.form_submit_button("Ambil skor & tambahkan")
    if submitted:
        from fetch_scores import fetch_cvss31, fetch_epss
        try:
            with st.spinner("Menghubungi NVD dan FIRST…"):
                cv = fetch_cvss31(cve_in)
                ep = fetch_epss(cve_in)
            new = pd.DataFrame([[id_in or f"K{len(st.session_state.current) + 1}", server_in, cve_in.strip().upper(),
                                 cv["cvss"], ep["epss"], kep, kep_t, exp, exp_t, cv["sumber_cvss"],
                                 ep["tanggal_epss"], ep["versi_epss"]]], columns=COLUMNS)
            st.session_state.data = pd.concat([st.session_state.current, new], ignore_index=True)
            st.session_state.pop("editor", None)
            st.success(f"{cve_in.upper()}: CVSS {cv['cvss']} ({cv['vektor']}), EPSS {ep['epss']} "
                       f"(tanggal {ep['tanggal_epss']}, model {ep['versi_epss']}). Diambil {date.today()}.")
            st.rerun()
        except Exception as e:  # jaringan/HTTP/format
            st.error(f"Gagal mengambil skor: {e}")

results, errors = evaluate_frame(st.session_state.get("current", st.session_state.data))
for e in errors:
    st.sidebar.warning(e)

# ---------- Tab: hasil ----------
with tab_hasil:
    table = ranking_table(results)
    if table.empty:
        st.info("Belum ada data valid.")
    else:
        m1, m2, m3 = st.columns(3)
        m1.metric("Pasangan CVE–server", len(table))
        m2.metric("CF > 0 (mendukung)", int((table["CF akhir"] > 0).sum()))
        m3.metric("CF < 0 (melemahkan)", int((table["CF akhir"] < 0).sum()))
        st.dataframe(
            table[["Urutan CF", "ID", "Server", "CVE", "CF akhir", "Interpretasi", "Aturan aktif",
                   "CVSS", "Urutan CVSS", "EPSS", "Urutan EPSS"]],
            width="stretch", hide_index=True,
            column_config={
                "CF akhir": st.column_config.NumberColumn(format="%.4f"),
                "EPSS": st.column_config.NumberColumn(format="%.5f"),
            },
        )
        st.caption("Peringkat seri berbagi nomor yang sama (1, 1, 3). Kasus dengan CF sama adalah prioritas setara; "
                   "urutan tampilan di antaranya tidak berarti beda prioritas.")

        st.subheader("Perbedaan urutan terhadap pembanding")
        diff_rows = []
        for _, r in table.iterrows():
            notes = []
            if r["Urutan CF"] != r["Urutan CVSS"]:
                notes.append(f"CVSS saja: #{r['Urutan CVSS']} → CF: #{r['Urutan CF']}")
            if r["Urutan CF"] != r["Urutan EPSS"]:
                notes.append(f"EPSS saja: #{r['Urutan EPSS']} → CF: #{r['Urutan CF']}")
            diff_rows.append({"ID": r["ID"], "Perubahan": "; ".join(notes) or "Posisi sama",
                              "Dijelaskan oleh aturan": r["Aturan aktif"]})
        st.dataframe(pd.DataFrame(diff_rows), width="stretch", hide_index=True)

        out = table.copy()
        out["Tanggal proses"] = str(date.today())
        st.download_button("⬇️ Unduh hasil prioritas (CSV)", out.to_csv(index=False).encode("utf-8"),
                           file_name="hasil_prioritas_cf.csv", mime="text/csv")

# ---------- Tab: rincian ----------
with tab_rinci:
    if not results:
        st.info("Belum ada data valid.")
    else:
        ids = [r.case_id for _, r in results]
        pick = st.selectbox("Pilih kasus", ids)
        row, res = next((row, r) for row, r in results if r.case_id == pick)
        st.markdown(f"**{res.case_id}** — {row['CVE']} pada {row['Server']}")
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
        else:
            st.write("Tidak ada aturan aktif.")
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
    for ex in EXAMPLES:
        r = evaluate(ex[0], ex[3], ex[4], ex[5], ex[6], ex[7], ex[8])
        diff = abs(r.cf_final - MANUAL[ex[0]])
        rows.append({"Kasus": ex[0], "Manual (paper)": MANUAL[ex[0]], "Sistem": round(r.cf_final, 6),
                     "Selisih": f"{diff:.1e}", "Status": "✅ Sesuai" if diff <= 1e-6 else "❌ Tidak sesuai"})
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.caption("Nilai manual Kasus C ditulis 0,5733 di paper (dibulatkan); nilai tepatnya 0,573333…")

"""Alur data: skenario CVE–server → isi skor asli → evaluasi CF → urutan.

Terpisah dari Streamlit supaya bisa diuji.
"""
from __future__ import annotations

from datetime import date

import pandas as pd

from cf_engine import competition_rank, evaluate
from fetch_scores import fetch_cvss_many, fetch_epss_many, is_real_cve

SCENARIO_COLUMNS = ["ID", "Server", "CVE", "Kepentingan", "Keyakinan kepentingan",
                    "Keterpaparan", "Keyakinan keterpaparan"]
SCORE_COLUMNS = ["CVSS", "EPSS", "Sumber CVSS", "Tanggal EPSS", "Versi EPSS", "Diambil", "Catatan"]
COLUMNS = SCENARIO_COLUMNS[:3] + ["CVSS", "EPSS"] + SCENARIO_COLUMNS[3:] + SCORE_COLUMNS[2:]


def normalize_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Lengkapi kolom yang hilang (CVSS/EPSS boleh kosong di file skenario)."""
    missing = [c for c in SCENARIO_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Kolom wajib hilang: {', '.join(missing)}")
    df = df.copy()
    for c in COLUMNS:
        if c not in df.columns:
            df[c] = None
    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")
    for c in ["Sumber CVSS", "Tanggal EPSS", "Versi EPSS", "Diambil", "Catatan"]:
        df[c] = df[c].astype(object).where(df[c].notna(), "")
    return df[COLUMNS].reset_index(drop=True)


def fill_scores(df: pd.DataFrame, epss_date: str | None = None, nvd_api_key: str | None = None,
                progress=None) -> tuple[pd.DataFrame, list[str]]:
    """Isi CVSS (NVD) dan EPSS (FIRST) untuk semua baris dengan kode CVE asli."""
    df = normalize_frame(df)
    log: list[str] = []
    cves = sorted({str(c).strip().upper() for c in df["CVE"] if is_real_cve(c)})
    if not cves:
        return df, ["Tidak ada kode CVE asli (format CVE-YYYY-NNNN) yang bisa diambil skornya."]

    epss = fetch_epss_many(cves, epss_date)
    cvss, cvss_fail = fetch_cvss_many(cves, nvd_api_key, progress)
    today = str(date.today())

    for i, row in df.iterrows():
        cve = str(row["CVE"]).strip().upper()
        if cve not in cves:
            continue
        notes = []
        if cve in cvss:
            df.at[i, "CVSS"] = cvss[cve]["cvss"]
            df.at[i, "Sumber CVSS"] = cvss[cve]["sumber_cvss"]
        else:
            df.at[i, "CVSS"] = float("nan")
            notes.append(f"CVSS: {cvss_fail.get(cve, 'tidak ada')}")
        if cve in epss:
            df.at[i, "EPSS"] = epss[cve]["epss"]
            df.at[i, "Tanggal EPSS"] = epss[cve]["tanggal_epss"]
            df.at[i, "Versi EPSS"] = epss[cve]["versi_epss"]
        else:
            df.at[i, "EPSS"] = float("nan")
            notes.append("EPSS: tidak tersedia" + (f" pada {epss_date}" if epss_date else ""))
        df.at[i, "Diambil"] = today
        df.at[i, "Catatan"] = "; ".join(notes) + (" → dikeluarkan dari kasus uji" if notes else "")
        if notes:
            log.append(f"{row['ID']} ({cve}): " + "; ".join(notes))
    log.insert(0, f"Skor diambil untuk {len(cves)} CVE unik: CVSS {len(cvss)} berhasil, "
                  f"EPSS {len(epss)} berhasil.")
    return df, log


def evaluate_frame(df: pd.DataFrame):
    results, errors = [], []
    for i, row in df.iterrows():
        rid = str(row.get("ID") or f"#{i + 1}")
        try:
            if pd.isna(row["CVSS"]) or pd.isna(row["EPSS"]):
                raise ValueError("CVSS atau EPSS kosong (isi manual atau ambil dari NVD & FIRST)")
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


def epss_two_dates(df: pd.DataFrame, date1: str, date2: str) -> tuple[pd.DataFrame, list[str]]:
    """Analisis tambahan Bab IV.B: EPSS dari dua tanggal, CVSS/kondisi server/aturan tetap."""
    df = normalize_frame(df)
    base = df[df["CVSS"].notna() & df["CVE"].apply(is_real_cve)].copy()
    if base.empty:
        return pd.DataFrame(), ["Butuh baris dengan CVE asli dan CVSS terisi."]
    cves = sorted({c.strip().upper() for c in base["CVE"]})
    e1, e2 = fetch_epss_many(cves, date1), fetch_epss_many(cves, date2)
    log = []
    rows = []
    for _, row in base.iterrows():
        cve = row["CVE"].strip().upper()
        if cve not in e1 or cve not in e2:
            log.append(f"{row['ID']} ({cve}): EPSS tidak tersedia di salah satu tanggal — dilewati.")
            continue
        r1 = evaluate(row["ID"], row["CVSS"], e1[cve]["epss"], row["Kepentingan"], row["Keyakinan kepentingan"],
                      row["Keterpaparan"], row["Keyakinan keterpaparan"])
        r2 = evaluate(row["ID"], row["CVSS"], e2[cve]["epss"], row["Kepentingan"], row["Keyakinan kepentingan"],
                      row["Keterpaparan"], row["Keyakinan keterpaparan"])
        rule1 = next(f.rule.code for f in r1.fired if f.rule.evidence == "EPSS")
        rule2 = next(f.rule.code for f in r2.fired if f.rule.evidence == "EPSS")
        rows.append({"ID": row["ID"], "CVE": cve, "Server": row["Server"],
                     f"EPSS {date1}": e1[cve]["epss"], f"EPSS {date2}": e2[cve]["epss"],
                     f"CF {date1}": r1.cf_final, f"CF {date2}": r2.cf_final,
                     "Aturan EPSS": rule1 if rule1 == rule2 else f"{rule1} → {rule2}"})
    t = pd.DataFrame(rows)
    if t.empty:
        return t, log
    t[f"Urutan {date1}"] = competition_rank(t[f"CF {date1}"].tolist())
    t[f"Urutan {date2}"] = competition_rank(t[f"CF {date2}"].tolist())
    t["Perubahan posisi"] = t[f"Urutan {date1}"] - t[f"Urutan {date2}"]
    return t.sort_values(f"Urutan {date2}").reset_index(drop=True), log

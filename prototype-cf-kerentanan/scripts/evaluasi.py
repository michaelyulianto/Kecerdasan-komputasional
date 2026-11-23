"""Evaluasi lengkap pada data uji paper (skenario_contoh.csv): CF, kesesuaian dengan perhitungan manual
independen, aktivasi aturan, perbandingan urutan (naik/turun/tetap, Kendall tau-b), kasus batas (Tabel VIII),
dan EPSS dua tanggal (Tabel IX). Menulis hasil ke folder hasil/.
Jalankan dari folder prototype-cf-kerentanan: python scripts/evaluasi.py"""
import itertools
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import pandas as pd  # noqa: E402
from cf_engine import evaluate  # noqa: E402
from manual_reference import W, emycin, manual_cf, rules_for  # noqa: E402
from pipeline import compare_two_dates, evaluate_frame, normalize_frame, ranking_table, tie_groups  # noqa: E402

OUT = ROOT / "hasil"
OUT.mkdir(exist_ok=True)
df = normalize_frame(pd.read_csv(ROOT / "skenario_contoh.csv"))
results, errors = evaluate_frame(df)
assert not errors, errors
t = ranking_table(results)
by_id = {r.case_id: (row, r) for row, r in results}

recs = []
for _, x in t.iterrows():
    row, r = by_id[x["ID"]]
    exp = next(e.category for e in r.evidences if e.name == "Keterpaparan")
    man = float(manual_cf(r_cvss := float(row["CVSS"]), r_epss := float(row["EPSS"]), exp))
    mvals = [W[k] for k in rules_for(r_cvss, r_epss, exp)]
    exp_eqs, acc = [], mvals[0]
    for v in mvals[1:]:
        exp_eqs.append(1 if acc >= 0 and v >= 0 else 2 if acc < 0 and v < 0 else 3)
        acc = emycin(acc, v)
    eqs = [s.equation for s in r.steps]
    recs.append({"kasus": r.case_id, "cve": row["CVE"], "server": row["Server"], "cvss": r_cvss, "epss": r_epss,
                 "kat_cvss": r.evidences[0].category, "kat_epss": r.evidences[1].category, "keterpaparan": exp,
                 "aturan_aktif": " ".join(f.rule.code for f in r.fired),
                 "cf_he": " ".join(f"{f.cf_he:+.1f}" for f in r.fired), "persamaan": " ".join(map(str, eqs)) or "-",
                 "aturan_sesuai_manual": [f.rule.code for f in r.fired] == rules_for(r_cvss, r_epss, exp),
                 "persamaan_sesuai": eqs == exp_eqs, "cf_sistem": r.cf_final, "cf_manual": man,
                 "selisih": abs(r.cf_final - man), "rank_cf": int(x["Urutan CF"]), "rank_cvss": int(x["Urutan CVSS"]),
                 "rank_epss": int(x["Urutan EPSS"])})
out = pd.DataFrame(recs)
out["urutan_tampil"] = range(1, len(out) + 1)
gerak = lambda a, b: ["naik" if p < q else "turun" if p > q else "tetap" for p, q in zip(out[a], out[b])]
out["vs_cvss"], out["vs_epss"] = gerak("rank_cf", "rank_cvss"), gerak("rank_cf", "rank_epss")
out.to_csv(OUT / "hasil_utama.csv", index=False)


def tau_b(a, b):
    nc = nd = ta = tb = 0
    for i, j in itertools.combinations(range(len(out)), 2):
        da, db = out[a][i] - out[a][j], out[b][i] - out[b][j]
        if da == 0 and db == 0:
            continue
        if da == 0:
            ta += 1
        elif db == 0:
            tb += 1
        elif (da > 0) == (db > 0):
            nc += 1
        else:
            nd += 1
    return (nc - nd) / math.sqrt((nc + nd + ta) * (nc + nd + tb))


steps = [s.equation for _, r in results for s in r.steps]
summary = {
    "jumlah_kasus": len(out), "jumlah_cve_unik": int(out.cve.nunique()), "jumlah_server": int(out.server.nunique()),
    "selisih_maks_vs_manual": float(out.selisih.max()), "lulus_1e-6": bool(out.selisih.max() <= 1e-6),
    "aturan_benar": int(out.aturan_sesuai_manual.sum()), "persamaan_benar": int(out.persamaan_sesuai.sum()),
    "aktivasi_aturan": int(sum(len(r.fired) for _, r in results)),
    "langkah_kombinasi": len(steps), "pemakaian_persamaan": {k: steps.count(k) for k in (1, 2, 3)},
    "nilai_cf_unik": int(out.cf_sistem.round(10).nunique()),
    "kelompok_setara": [(rk, round(cf, 4), ids) for rk, cf, ids in tie_groups(t)],
    "gerak_vs_cvss": out.vs_cvss.value_counts().to_dict(), "gerak_vs_epss": out.vs_epss.value_counts().to_dict(),
    "kendall_tau_b_cf_cvss": round(tau_b("rank_cf", "rank_cvss"), 4),
    "kendall_tau_b_cf_epss": round(tau_b("rank_cf", "rank_epss"), 4),
}

batas = []
for c, e, x in [(6.9, 0.05, "Controlled"), (7.0, 0.05, "Controlled"), (7.5, 0.0999, "Controlled"),
                (7.5, 0.1, "Controlled"), (9.8, 0.09999, "Open"), (9.8, 0.1, "Open")]:
    r = evaluate("B", c, e, x)
    batas.append({"cvss": c, "epss": e, "keterpaparan": x, "aturan": " ".join(f.rule.code for f in r.fired),
                  "cf": round(r.cf_final, 4), "manual": round(float(manual_cf(c, e, x)), 4)})
pd.DataFrame(batas).to_csv(OUT / "kasus_batas.csv", index=False)

load = lambda f: {r.cve: {"epss": float(r.epss)} for r in pd.read_csv(ROOT / "data" / f).itertuples()}
dua, log = compare_two_dates(df, load("epss_2026-08-22.csv"), load("epss_2026-11-22.csv"), "2026-08-22", "2026-11-22")
dua.to_csv(OUT / "epss_dua_tanggal.csv", index=False)
berubah = dua[dua["Aturan EPSS"].str.contains("→")]
summary["dua_tanggal_kategori_berubah"] = berubah[["ID", "EPSS 2026-08-22", "EPSS 2026-11-22", "CF 2026-08-22",
    "CF 2026-11-22", "Urutan 2026-08-22", "Urutan 2026-11-22", "Urutan EPSS saja 2026-08-22",
    "Urutan EPSS saja 2026-11-22"]].round(5).to_dict("records")
summary["dua_tanggal_cf_tetap"] = int(((dua["CF 2026-08-22"] - dua["CF 2026-11-22"]).abs() < 1e-12).sum())
(OUT / "ringkasan.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False, default=int), encoding="utf-8")

pd.set_option("display.width", 220)
print(out[["kasus", "cve", "server", "cvss", "epss", "keterpaparan", "aturan_aktif", "cf_sistem", "rank_cf",
           "rank_cvss", "rank_epss", "vs_cvss", "vs_epss"]].to_string(index=False))
print(json.dumps(summary, indent=1, ensure_ascii=False, default=int))
print(pd.DataFrame(batas).to_string(index=False))

"""Tes sesuai paper final: contoh III.C, toleransi 1e-6 terhadap perhitungan manual independen
(tests/manual_reference.py, pecahan eksak), kasus batas (Tabel VIII), dan independensi urutan."""
import itertools
import os
import random
import sys

import pandas as pd
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from cf_engine import RULES, categorize_cvss, categorize_epss, categorize_exposure, combine, evaluate  # noqa: E402
from manual_reference import manual_cf, rules_for  # noqa: E402
from pipeline import evaluate_frame, normalize_frame, ranking_table, tie_groups  # noqa: E402

TOL = 1e-6


def combine_all(values):
    acc = values[0]
    for v in values[1:]:
        acc, _ = combine(acc, v)
    return acc


PAPER_EXAMPLES = [  # (kasus, CVSS, EPSS, keterpaparan, aturan aktif, CF akhir eksak) — Bagian III.C
    ("A", 9.8, 0.94, "Open", ["R1", "R4", "R6"], 0.968),
    ("B", 5.3, 0.004, "Small", ["R5", "R7"], -0.64),
    ("C", 9.8, 0.004, "Open", ["R1", "R5", "R6"], 11 / 15),
]


@pytest.mark.parametrize("cid,cvss,epss,exp,rules,expected", PAPER_EXAMPLES)
def test_contoh_iii_c_vs_manual(cid, cvss, epss, exp, rules, expected):
    r = evaluate(cid, cvss, epss, exp)
    assert [f.rule.code for f in r.fired] == rules
    assert abs(r.cf_final - expected) <= TOL
    assert abs(r.cf_final - float(manual_cf(cvss, epss, exp))) <= TOL


def test_urutan_contoh_tabel_v():
    df = pd.DataFrame([[c, "s", "x", cv, ep, ex] for c, cv, ep, ex, *_ in PAPER_EXAMPLES],
                      columns=["ID", "Server", "CVE", "CVSS", "EPSS", "Keterpaparan"])
    t = ranking_table(evaluate_frame(normalize_frame(df))[0]).set_index("ID")
    assert (t.loc["A", "Urutan CF"], t.loc["C", "Urutan CF"], t.loc["B", "Urutan CF"]) == (1, 2, 3)
    assert t.loc["A", "Urutan CVSS"] == t.loc["C", "Urutan CVSS"] == 1
    assert t.loc["B", "Urutan EPSS"] == t.loc["C", "Urutan EPSS"] == 2


@pytest.mark.parametrize("score,cat", [(6.9, "Medium"), (7.0, "High"), (8.9, "High"), (9.0, "Critical"),
                                        (3.9, "Low"), (4.0, "Medium"), (0.1, "Low"), (10.0, "Critical")])
def test_batas_cvss(score, cat):
    assert categorize_cvss(score) == cat


@pytest.mark.parametrize("p,cat", [(0.0999, "Rendah"), (0.09999, "Rendah"), (0.1, "Tinggi"), (0.10001, "Tinggi")])
def test_batas_epss(p, cat):
    assert categorize_epss(p) == cat


TABEL_VIII = [(6.9, 0.05, "Controlled", ["R5"], -0.4), (7.0, 0.05, "Controlled", ["R2", "R5"], 0.0),
              (7.5, 0.0999, "Controlled", ["R2", "R5"], 0.0), (7.5, 0.1, "Controlled", ["R2", "R4"], 0.88),
              (9.8, 0.09999, "Open", ["R1", "R5", "R6"], 11 / 15), (9.8, 0.1, "Open", ["R1", "R4", "R6"], 0.968)]


@pytest.mark.parametrize("cvss,epss,exp,rules,cf", TABEL_VIII)
def test_tabel_viii(cvss, epss, exp, rules, cf):
    r = evaluate("B", cvss, epss, exp)
    assert [f.rule.code for f in r.fired] == rules and abs(r.cf_final - cf) <= TOL


def test_cvss_none_ditolak():
    with pytest.raises(ValueError):
        evaluate("x", 0.0, 0.5, "Open")


SCORES = [0.1, 2.5, 3.9, 4.0, 5.3, 6.9, 7.0, 7.5, 8.9, 9.0, 9.8, 10.0]
EPSSES = [0.0, 0.004, 0.0999, 0.1, 0.10015, 0.5, 0.99999]
EXPS = ["Open", "Controlled", "Small", "Tidak diketahui"]


def test_336_kombinasi_vs_manual():
    combos = list(itertools.product(SCORES, EPSSES, EXPS))
    assert len(combos) == 336
    mx = 0.0
    for c, e, x in combos:
        r = evaluate("x", c, e, x)
        xm = categorize_exposure(x)[0]
        assert [f.rule.code for f in r.fired] == rules_for(c, e, xm)
        mx = max(mx, abs(r.cf_final - float(manual_cf(c, e, xm))))
    assert mx <= TOL


def test_15_kasus_uji_vs_manual_dan_tabel_vii():
    df = pd.read_csv(os.path.join(ROOT, "skenario_contoh.csv"))
    results, errors = evaluate_frame(normalize_frame(df))
    assert len(results) == 15 and not errors
    mx = max(abs(r.cf_final - float(manual_cf(row["CVSS"], row["EPSS"], row["Keterpaparan"]))) for row, r in results)
    assert mx <= TOL
    t = ranking_table(results)
    assert t["ID"].tolist()[:3] == ["K01", "K02", "K15"]
    assert [(rk, ids) for rk, _, ids in tie_groups(t)] == [(1, ["K01", "K02"]), (5, ["K05", "K06"]), (8, ["K10", "K08"])]
    assert sum(len(r.fired) for _, r in results) == 37
    eqs = [s.equation for _, r in results for s in r.steps]
    assert (len(eqs), eqs.count(1), eqs.count(2), eqs.count(3)) == (22, 12, 3, 7)


def test_pemilihan_persamaan():
    assert combine(0.5, 0.2)[1] == 1 and combine(0.0, 0.2)[1] == 1
    assert combine(-0.5, -0.2)[1] == 2
    assert combine(0.5, -0.2)[1] == 3 and combine(-0.5, 0.2)[1] == 3


def test_bobot_aturan_tabel_iii():
    assert [(r.code, r.cf) for r in RULES] == [("R1", 0.6), ("R2", 0.4), ("R3", -0.4), ("R4", 0.8),
                                               ("R5", -0.4), ("R6", 0.6), ("R7", -0.4)]
    assert all(abs(r.cf) <= 0.8 for r in RULES)


def test_independensi_urutan_semua_himpunan_aturan():
    vals = [r.cf for r in RULES]
    for k in range(1, 4):
        for subset in itertools.combinations(vals, k):
            res = [combine_all(list(p)) for p in itertools.permutations(subset)]
            assert max(res) - min(res) < 1e-12


def test_independensi_urutan_200000_acak():
    rnd = random.Random(20261123)
    mx = 0.0
    for _ in range(200_000):
        v = [rnd.uniform(-0.8, 0.8) for _ in range(3)]
        res = [combine_all(list(p)) for p in itertools.permutations(v)]
        mx = max(mx, max(res) - min(res))
    assert mx < 1e-14

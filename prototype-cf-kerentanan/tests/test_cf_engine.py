import itertools
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cf_engine import categorize_cvss, categorize_epss, combine, competition_rank, evaluate  # noqa: E402

TOL = 1e-6  # toleransi pada paper (Bagian IV.C)


def test_contoh_paper_kasus_a():
    r = evaluate("A", 9.8, 0.94, "Open")
    assert [f.rule.code for f in r.fired] == ["R1", "R4", "R6"]
    assert [round(s.result, 6) for s in r.steps] == [0.92, 0.968]
    assert abs(r.cf_final - 0.968) <= TOL


def test_contoh_paper_kasus_b_negatif():
    r = evaluate("B", 5.3, 0.004, "Small")
    assert [f.rule.code for f in r.fired] == ["R5", "R7"]
    assert all(s.equation == 2 for s in r.steps)
    assert abs(r.cf_final - (-0.64)) <= TOL


def test_contoh_paper_kasus_c_bertentangan():
    r = evaluate("C", 9.8, 0.004, "Open")
    assert [(f.rule.code, round(f.cf_he, 6)) for f in r.fired] == [("R1", 0.6), ("R5", -0.4), ("R6", 0.6)]
    assert r.steps[0].equation == 3
    assert abs(r.cf_final - 11 / 15) <= TOL


def test_batas_kategori():
    assert categorize_cvss(9.0) == "Critical" and categorize_cvss(8.9) == "High"
    assert categorize_cvss(7.0) == "High" and categorize_cvss(6.9) == "Medium"
    assert categorize_cvss(4.0) == "Medium" and categorize_cvss(3.9) == "Low"
    assert categorize_cvss(0.0) == "None"
    assert categorize_epss(0.1) == "Tinggi" and categorize_epss(0.0999) == "Rendah"
    with pytest.raises(ValueError):
        categorize_cvss(10.5)
    with pytest.raises(ValueError):
        categorize_epss(1.2)


def test_cf_e_satu_dan_ambang_premis():
    r = evaluate("D", 9.8, 0.5, "Open")
    assert all(e.cf_e == 1.0 for e in r.evidences)
    assert all(f.cf_he == f.rule.cf for f in r.fired) and r.not_fired == []


def test_keterpaparan_tidak_diketahui_jadi_open():
    for v in ("Tidak diketahui", "", None):
        r = evaluate("E", 5.0, 0.05, v)
        assert "R6" in [f.rule.code for f in r.fired]


def test_satu_aturan_aktif():
    # CVSS Medium dan Controlled netral; EPSS selalu mengaktifkan R4 atau R5
    r = evaluate("F", 5.0, 0.2, "Controlled")
    assert [f.rule.code for f in r.fired] == ["R4"] and r.steps == []


def test_kombinasi_tidak_bergantung_urutan():
    rnd = random.Random(0)
    for _ in range(2000):
        vals = [rnd.uniform(-0.8, 0.8) for _ in range(4)]
        results = set()
        for perm in itertools.permutations(vals):
            c = perm[0]
            for v in perm[1:]:
                c, _ = combine(c, v)
            results.add(round(c, 9))
        assert len(results) == 1


def test_konflik_total():
    with pytest.raises(ZeroDivisionError):
        combine(1.0, -1.0)


def test_peringkat_seri():
    assert competition_rank([9.8, 9.8, 5.3]) == [1, 1, 3]
    assert competition_rank([0.94, 0.004, 0.004]) == [1, 2, 2]

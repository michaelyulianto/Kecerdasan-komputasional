import os
import sys

import pandas as pd
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import fetch_scores  # noqa: E402
import mock_api  # noqa: E402
from pipeline import epss_two_dates, evaluate_frame, fill_scores, normalize_frame, ranking_table  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def mock_server():
    srv = mock_api.start(8766)
    fetch_scores.NVD_URL = "http://127.0.0.1:8766/nvd"
    fetch_scores.EPSS_URL = "http://127.0.0.1:8766/epss"
    fetch_scores.NVD_DELAY = 0
    yield
    srv.shutdown()


def scenario():
    # skenario contoh tanpa skor tersimpan + dua baris tambahan untuk menguji pengecualian
    df = pd.read_csv(os.path.join(os.path.dirname(HERE), "skenario_contoh.csv"))[["ID", "Server", "CVE", "Keterpaparan"]]
    extra = pd.DataFrame([["X1", "srv-dev", "CVE-2024-3094", "Small"], ["X2", "srv-dev", "CVE-2099-0001", ""]],
                         columns=df.columns)
    return pd.concat([df, extra], ignore_index=True)


def test_skenario_tanpa_skor_dilewati():
    _, errors = evaluate_frame(normalize_frame(scenario()))
    assert len(errors) == len(scenario())


def test_fill_scores_dan_pengecualian():
    df, log = fill_scores(scenario())
    heart = df[df["CVE"] == "CVE-2014-0160"].iloc[0]
    assert pd.isna(heart["CVSS"]) and "dikeluarkan" in heart["Catatan"]
    xz = df[df["CVE"] == "CVE-2024-3094"].iloc[0]
    assert pd.isna(xz["EPSS"]) and "EPSS" in xz["Catatan"]
    log4j = df[df["CVE"] == "CVE-2021-44228"]
    assert log4j["CVSS"].notna().all() and log4j["Tanggal EPSS"].ne("").all()
    results, errors = evaluate_frame(df)
    cna = df[df["CVE"] == "CVE-2099-0001"].iloc[0]  # hanya skor CNA → dikeluarkan
    assert pd.isna(cna["CVSS"]) and "Primary" in cna["Catatan"]
    assert len(results) == len(df) - 3 and len(errors) == 3
    t = ranking_table(results)
    # CVE sama, keterpaparan beda → CF beda (inti paper: K15 Open vs K08 Small)
    k15 = t[t.ID == "K15"]["CF akhir"].iloc[0]
    k08 = t[t.ID == "K08"]["CF akhir"].iloc[0]
    assert k15 > k08


def test_epss_tanggal_tertentu_dan_versi():
    df, _ = fill_scores(scenario(), epss_date="2025-06-01")
    assert (df["Tanggal EPSS"].replace("", None).dropna() == "2025-06-01").all()
    assert df["Versi EPSS"].replace("", None).dropna().str.startswith("v4").all()
    df2, _ = fill_scores(scenario(), epss_date="2026-08-22")
    assert df2["Versi EPSS"].replace("", None).dropna().str.startswith("v5").all()


def test_epss_dua_tanggal():
    df, _ = fill_scores(scenario())
    t, log = epss_two_dates(df, "2025-06-01", "2026-11-16")
    assert not t.empty and "Perubahan posisi" in t.columns
    assert any("CVE-2024-3094" in line for line in log)

"""Pengambilan skor CVSS v3.1 dari NVD dan EPSS dari FIRST.

Sesuai paper (Bab IV.A):
- hanya CVSS v3.1 Base Score yang dipakai, tanpa konversi antarversi;
- CVE tanpa CVSS v3.1 atau tanpa EPSS tidak disertakan;
- tanggal pengambilan data dan versi model EPSS dicatat.

API yang dipakai:
- NVD CVE API 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...
  Batas tanpa API key 5 permintaan / 30 detik, dengan API key 50 / 30 detik.
- FIRST EPSS API  : https://api.first.org/data/v1/epss?cve=A,B,...&date=YYYY-MM-DD
  Maksimal 100 CVE per permintaan; parameter `date` mengambil skor historis.
"""
from __future__ import annotations

import os
import re
import time
from datetime import date

import requests

NVD_URL = os.environ.get("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_URL = os.environ.get("EPSS_URL", "https://api.first.org/data/v1/epss")
NVD_DELAY = float(os.environ.get("NVD_DELAY", "6"))  # detik antar permintaan tanpa API key
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_BATCH = 100


def is_real_cve(cve) -> bool:
    return isinstance(cve, str) and bool(CVE_RE.match(cve.strip().upper()))


def normalize_cve(cve: str) -> str:
    cve = str(cve).strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"Format CVE tidak valid: {cve!r} (contoh: CVE-2021-44228)")
    return cve


def epss_model_version(score_date: str) -> str:
    """Versi model EPSS disimpulkan dari tanggal skor (v4 rilis 17 Mar 2025, v3 rilis 7 Mar 2023)."""
    if not score_date:
        return "-"
    if score_date >= "2025-03-17":
        return "v4 (disimpulkan dari tanggal)"
    if score_date >= "2023-03-07":
        return "v3 (disimpulkan dari tanggal)"
    return "v1/v2 (disimpulkan dari tanggal)"


def fetch_cvss31(cve: str, api_key: str | None = None, timeout: float = 30) -> dict:
    """Mengembalikan {'cvss', 'sumber_cvss', 'vektor'}; ValueError jika tidak ada CVSS v3.1."""
    cve = normalize_cve(cve)
    headers = {"apiKey": api_key} if api_key else {}
    r = requests.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=timeout)
    if r.status_code in (403, 429):
        raise RuntimeError("NVD menolak karena batas permintaan; tunggu 30 detik atau pakai API key NVD")
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"{cve} tidak ditemukan di NVD")
    metrics = vulns[0]["cve"].get("metrics", {}).get("cvssMetricV31", [])
    if not metrics:
        raise ValueError(f"{cve} tidak memiliki CVSS v3.1 di NVD → tidak disertakan (batasan paper)")
    chosen = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    data = chosen["cvssData"]
    return {"cvss": float(data["baseScore"]), "sumber_cvss": f"NVD ({chosen.get('source', '-')})",
            "vektor": data.get("vectorString", "")}


def fetch_epss_many(cves: list[str], on_date: str | None = None, timeout: float = 30) -> dict[str, dict]:
    """EPSS untuk banyak CVE sekaligus. on_date = 'YYYY-MM-DD' untuk skor historis, None = terbaru.

    Mengembalikan {cve: {'epss', 'tanggal_epss', 'versi_epss'}}; CVE tanpa skor tidak ada di hasil.
    """
    cves = sorted({normalize_cve(c) for c in cves})
    out: dict[str, dict] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        params = {"cve": ",".join(cves[i:i + EPSS_BATCH]), "limit": EPSS_BATCH}
        if on_date:
            params["date"] = on_date
        r = requests.get(EPSS_URL, params=params, timeout=timeout)
        r.raise_for_status()
        j = r.json()
        for d in j.get("data", []):
            score_date = d.get("date") or on_date or str(date.today())
            out[d["cve"].upper()] = {
                "epss": float(d["epss"]),
                "tanggal_epss": score_date,
                "versi_epss": d.get("model_version") or j.get("model_version") or epss_model_version(score_date),
            }
    return out


def fetch_epss(cve: str, on_date: str | None = None, timeout: float = 30) -> dict:
    cve = normalize_cve(cve)
    res = fetch_epss_many([cve], on_date, timeout)
    if cve not in res:
        raise ValueError(f"{cve} tidak memiliki skor EPSS di FIRST" + (f" pada {on_date}" if on_date else ""))
    return res[cve]


def fetch_cvss_many(cves: list[str], api_key: str | None = None, progress=None) -> tuple[dict, dict]:
    """CVSS v3.1 untuk banyak CVE, dengan jeda sesuai batas NVD.

    Mengembalikan (hasil {cve: dict}, gagal {cve: alasan}).
    """
    cves = sorted({normalize_cve(c) for c in cves})
    delay = 0.7 if api_key else NVD_DELAY
    ok, fail = {}, {}
    for n, cve in enumerate(cves):
        if progress:
            progress(n, len(cves), cve)
        for attempt in range(2):
            try:
                ok[cve] = fetch_cvss31(cve, api_key)
                break
            except RuntimeError as e:  # batas permintaan → tunggu lalu coba sekali lagi
                if attempt == 0:
                    time.sleep(30)
                else:
                    fail[cve] = str(e)
            except Exception as e:
                fail[cve] = str(e)
                break
        if n < len(cves) - 1:
            time.sleep(delay)
    return ok, fail

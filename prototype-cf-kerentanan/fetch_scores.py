"""Pengambilan skor CVSS v3.1 dari NVD dan EPSS dari FIRST.

Sesuai paper: hanya CVSS v3.1 Base Score yang dipakai (tanpa konversi antarversi),
dan tanggal serta versi model EPSS dicatat.
"""
from __future__ import annotations

import re
from datetime import date

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_cve(cve: str) -> str:
    cve = cve.strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"Format CVE tidak valid: {cve!r} (contoh: CVE-2021-44228)")
    return cve


def fetch_cvss31(cve: str, timeout: float = 20) -> dict:
    """Mengembalikan {'cvss', 'sumber_cvss', 'vektor'} atau raise ValueError jika tidak ada v3.1."""
    cve = normalize_cve(cve)
    r = requests.get(NVD_URL, params={"cveId": cve}, timeout=timeout)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"{cve} tidak ditemukan di NVD")
    metrics = vulns[0]["cve"].get("metrics", {}).get("cvssMetricV31", [])
    if not metrics:
        raise ValueError(f"{cve} tidak memiliki CVSS v3.1 di NVD → tidak disertakan (sesuai batasan paper)")
    chosen = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    data = chosen["cvssData"]
    return {"cvss": float(data["baseScore"]), "sumber_cvss": f"NVD ({chosen.get('source', '-')})",
            "vektor": data.get("vectorString", "")}


def fetch_epss(cve: str, timeout: float = 20) -> dict:
    """Mengembalikan {'epss', 'tanggal_epss', 'versi_epss'}."""
    cve = normalize_cve(cve)
    r = requests.get(EPSS_URL, params={"cve": cve}, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    data = j.get("data", [])
    if not data:
        raise ValueError(f"{cve} tidak memiliki skor EPSS di FIRST")
    d = data[0]
    return {"epss": float(d["epss"]), "tanggal_epss": d.get("date", str(date.today())),
            "versi_epss": j.get("model_version") or d.get("model_version") or "-"}

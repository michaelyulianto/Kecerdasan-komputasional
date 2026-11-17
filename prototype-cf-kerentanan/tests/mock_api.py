"""Server tiruan NVD & FIRST untuk pengujian tanpa internet.

Jalankan: python tests/mock_api.py 8765
Lalu: NVD_URL=http://localhost:8765/nvd EPSS_URL=http://localhost:8765/epss NVD_DELAY=0 streamlit run app.py
Nilai skor di sini BUKAN data asli.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

NO_V31 = {"CVE-2014-0160"}  # disimulasikan tidak punya CVSS v3.1
NO_EPSS = {"CVE-2024-3094"}  # disimulasikan tidak punya EPSS


def fake_cvss(cve):
    return round(3.0 + (sum(map(ord, cve)) % 70) / 10, 1)


def fake_epss(cve, d):
    base = (sum(map(ord, cve)) % 97) / 100
    return round(base * (0.5 if d and d < "2026-01-01" else 1.0), 5)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/nvd":
            cve = q["cveId"][0]
            metrics = {} if cve in NO_V31 else {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                       "cvssData": {"baseScore": fake_cvss(cve), "vectorString": "CVSS:3.1/MOCK"}}]}
            body = {"vulnerabilities": [{"cve": {"id": cve, "metrics": metrics}}]}
        else:
            d = q.get("date", ["2026-11-16"])[0]
            body = {"status": "OK", "data": [{"cve": c, "epss": str(fake_epss(c, d)), "date": d}
                                             for c in q["cve"][0].split(",") if c not in NO_EPSS]}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def start(port):
    srv = HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()

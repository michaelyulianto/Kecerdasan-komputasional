"""Mesin inferensi Certainty Factor untuk prioritisasi pasangan CVE–server.

Mengikuti rancangan paper (Bagian III):
- Tabel I  : kategori penilaian evidence (CVSS v3.1 Base, EPSS, keterpaparan server)
- Tabel II : skala interpretasi istilah CF (Sutojo dkk., 2011), dipakai untuk memilih CF(Rule)
- Tabel III: basis aturan R1–R7, satu premis per aturan
- CF(E) = 1,0 untuk semua evidence karena kategorinya ditentukan secara deterministik
- Ambang premis EMYCIN: aturan aktif hanya jika CF(E) > 0,2
- Fungsi kombinasi EMYCIN untuk nilai positif, negatif, dan beda tanda

Nilai CF akhir adalah skor dukungan berbasis aturan, BUKAN probabilitas eksploitasi.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CF_THRESHOLD = 0.2  # ambang premis EMYCIN
CF_E = 1.0  # CF(E) seluruh evidence (Bagian III.B.2)
HYPOTHESIS = "Pasangan CVE–server perlu ditangani dengan prioritas tinggi"

# Tabel II — skala interpretasi istilah CF
TERM_SCALE = [
    ("Pasti tidak", -1.0),
    ("Hampir pasti tidak", -0.8),
    ("Kemungkinan besar tidak", -0.6),
    ("Mungkin tidak", -0.4),
    ("Tidak tahu", 0.0),  # rentang −0,2 s.d. 0,2; setara kategori netral (tanpa aturan)
    ("Mungkin", 0.4),
    ("Kemungkinan besar", 0.6),
    ("Hampir pasti", 0.8),
    ("Pasti", 1.0),
]
KETERPAPARAN = ["Open", "Controlled", "Small", "Tidak diketahui"]


@dataclass(frozen=True)
class Rule:
    code: str
    evidence: str  # "CVSS" | "EPSS" | "Keterpaparan"
    category: str
    cf: float
    term: str

    @property
    def text(self) -> str:
        label = {"EPSS": "EPSS", "CVSS": "CVSS"}.get(self.evidence, self.evidence)
        cond = {"Tinggi": "≥ 0,1", "Rendah": "< 0,1"}[self.category] if self.evidence == "EPSS" else f"= {self.category}"
        return f"IF {label} {cond} THEN H"


# Tabel III — basis aturan
RULES = [
    Rule("R1", "CVSS", "Critical", 0.6, "Kemungkinan besar"),
    Rule("R2", "CVSS", "High", 0.4, "Mungkin"),
    Rule("R3", "CVSS", "Low", -0.4, "Mungkin tidak"),
    Rule("R4", "EPSS", "Tinggi", 0.8, "Hampir pasti"),
    Rule("R5", "EPSS", "Rendah", -0.4, "Mungkin tidak"),
    Rule("R6", "Keterpaparan", "Open", 0.6, "Kemungkinan besar"),
    Rule("R7", "Keterpaparan", "Small", -0.4, "Mungkin tidak"),
]


# ---------- Tabel I — penilaian evidence ----------
def categorize_cvss(score: float) -> str:
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS harus 0–10, didapat {score}")
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "None"


def categorize_epss(p: float) -> str:
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"EPSS harus 0–1, didapat {p}")
    return "Tinggi" if p >= 0.1 else "Rendah"


def categorize_exposure(value) -> tuple[str, str]:
    """SSVC System Exposure. Kosong/tidak diketahui → Open (pedoman SSVC). Mengembalikan (kategori, catatan)."""
    v = "" if value is None else str(value).strip()
    if v.lower() in ("", "nan", "none", "tidak diketahui", "unknown"):
        return "Open", "Keterpaparan tidak diketahui → diasumsikan Open (pedoman SSVC)"
    v = v.capitalize()
    if v not in ("Open", "Controlled", "Small"):
        raise ValueError(f"Keterpaparan tidak dikenal: {value!r} (pilihan: Open, Controlled, Small, Tidak diketahui)")
    return v, "Skenario simulasi, kategori deterministik"


# ---------- Fungsi kombinasi EMYCIN ----------
def combine(cf1: float, cf2: float) -> tuple[float, int]:
    """Gabungkan dua CF. Mengembalikan (hasil, nomor persamaan 1/2/3)."""
    if cf1 >= 0 and cf2 >= 0:
        return cf1 + cf2 * (1 - cf1), 1
    if cf1 < 0 and cf2 < 0:
        return cf1 + cf2 * (1 + cf1), 2
    denom = 1 - min(abs(cf1), abs(cf2))
    if denom == 0:
        raise ZeroDivisionError("Konflik total (CF = 1 dan CF = −1): kombinasi tidak terdefinisi")
    return (cf1 + cf2) / denom, 3


def _fmt(x: float, nd: int = 4) -> str:
    s = f"{x:.{nd}f}".rstrip("0").rstrip(".")
    if s in ("-0", ""):
        s = "0"
    return s.replace(".", ",").replace("-", "−")


def combine_formula(cf1: float, cf2: float, eq: int, result: float) -> str:
    a, b, r = _fmt(cf1), _fmt(cf2), _fmt(result)
    if eq == 1:
        return f"{a} + {b}(1 − {a}) = {r}"
    if eq == 2:
        return f"{a} + ({b})(1 + ({a})) = {r}"
    return f"({a} + ({b})) / (1 − min(|{a}|; |{b}|)) = {r}"


# ---------- Struktur hasil ----------
@dataclass
class Evidence:
    name: str
    raw: str
    category: str
    cf_e: float
    note: str = ""


@dataclass
class FiredRule:
    rule: Rule
    cf_e: float
    cf_he: float


@dataclass
class Step:
    cf1: float
    cf2: float
    equation: int
    result: float
    rule_code: str

    @property
    def formula(self) -> str:
        return combine_formula(self.cf1, self.cf2, self.equation, self.result)


@dataclass
class Result:
    case_id: str
    evidences: list[Evidence]
    fired: list[FiredRule]
    not_fired: list[tuple[Rule, str]]
    steps: list[Step]
    cf_final: float
    warnings: list[str] = field(default_factory=list)


def evaluate(case_id: str, cvss: float, epss: float, keterpaparan) -> Result:
    warnings: list[str] = []
    cvss_cat = categorize_cvss(float(cvss))
    if cvss_cat == "None":
        raise ValueError("CVSS 0,0 (None) tidak menyatakan kerentanan dan tidak disertakan")
    epss_cat = categorize_epss(float(epss))
    exp_cat, exp_note = categorize_exposure(keterpaparan)
    exp_raw = "Tidak diketahui" if exp_note.startswith("Keterpaparan tidak") else exp_cat

    evidences = [
        Evidence("CVSS", _fmt(float(cvss), 1), cvss_cat, CF_E, "Skor NVD, kategori deterministik"),
        Evidence("EPSS", _fmt(float(epss), 5), epss_cat, CF_E, "Skor FIRST, kategori deterministik"),
        Evidence("Keterpaparan", exp_raw, exp_cat, CF_E, exp_note),
    ]
    ev_by_name = {e.name: e for e in evidences}

    fired: list[FiredRule] = []
    not_fired: list[tuple[Rule, str]] = []
    for rule in RULES:
        ev = ev_by_name[rule.evidence]
        if ev.category != rule.category:
            continue  # premis tidak cocok — bukan kandidat
        if ev.cf_e > CF_THRESHOLD:
            fired.append(FiredRule(rule, ev.cf_e, ev.cf_e * rule.cf))
        else:
            not_fired.append((rule, f"CF(E) = {_fmt(ev.cf_e)} ≤ {_fmt(CF_THRESHOLD)} (ambang EMYCIN)"))

    steps: list[Step] = []
    cf = 0.0
    if fired:
        cf = fired[0].cf_he
        for fr in fired[1:]:
            new, eq = combine(cf, fr.cf_he)
            steps.append(Step(cf, fr.cf_he, eq, new, fr.rule.code))
            cf = new

    return Result(case_id, evidences, fired, not_fired, steps, cf, warnings)


def competition_rank(values: list[float], tol: float = 1e-9) -> list[int]:
    """Peringkat menurun dengan nilai seri berbagi peringkat (1, 1, 3, ...)."""
    out = []
    for v in values:
        out.append(1 + sum(1 for w in values if w - v > tol))
    return out

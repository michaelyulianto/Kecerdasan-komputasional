"""Mesin inferensi Certainty Factor untuk prioritisasi pasangan CVE–server.

Mengikuti rancangan paper (Bagian III):
- Tabel I  : kategori penilaian evidence (CVSS v3.1, EPSS, kepentingan, keterpaparan)
- Tabel II : skala interpretasi istilah CF (Sutojo dkk., 2011)
- Tabel III: basis aturan R1–R9, satu premis per aturan
- Ambang premis EMYCIN: aturan aktif hanya jika CF(E) > 0,2
- Fungsi kombinasi EMYCIN untuk nilai positif, negatif, dan beda tanda
"""
from __future__ import annotations

from dataclasses import dataclass, field

CF_THRESHOLD = 0.2  # ambang premis EMYCIN
HYPOTHESIS = "Pasangan CVE–server perlu ditangani dengan prioritas tinggi"

# Tabel II — skala interpretasi istilah CF
TERM_SCALE = [
    ("Pasti tidak", -1.0),
    ("Hampir pasti tidak", -0.8),
    ("Kemungkinan besar tidak", -0.6),
    ("Mungkin tidak", -0.4),
    ("Tidak tahu", 0.0),  # rentang −0,2 s.d. 0,2; tidak pernah mengaktifkan aturan
    ("Mungkin", 0.4),
    ("Kemungkinan besar", 0.6),
    ("Hampir pasti", 0.8),
    ("Pasti", 1.0),
]
# Istilah keyakinan yang dapat dipilih pengguna untuk kondisi server, yaitu CF(E)
CONFIDENCE_TERMS = {"Pasti": 1.0, "Hampir pasti": 0.8, "Kemungkinan besar": 0.6, "Mungkin": 0.4, "Tidak tahu": 0.0}

KEPENTINGAN = ["Tinggi", "Sedang", "Rendah"]
KETERPAPARAN = ["Open", "Controlled", "Small", "Tidak diketahui"]


@dataclass(frozen=True)
class Rule:
    code: str
    evidence: str  # "CVSS" | "EPSS" | "Kepentingan" | "Keterpaparan"
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
    Rule("R6", "Kepentingan", "Tinggi", 0.4, "Mungkin"),
    Rule("R7", "Kepentingan", "Rendah", -0.4, "Mungkin tidak"),
    Rule("R8", "Keterpaparan", "Open", 0.6, "Kemungkinan besar"),
    Rule("R9", "Keterpaparan", "Small", -0.4, "Mungkin tidak"),
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


def evaluate(case_id: str, cvss: float, epss: float, kepentingan: str, kepentingan_term: str,
             keterpaparan: str, keterpaparan_term: str) -> Result:
    warnings: list[str] = []
    cvss_cat = categorize_cvss(float(cvss))
    if cvss_cat == "None":
        warnings.append("CVSS 0,0 (None) tidak menyatakan kerentanan; menurut paper kasus ini tidak disertakan.")
    epss_cat = categorize_epss(float(epss))

    exp_cat, exp_note = keterpaparan, ""
    exp_cf = CONFIDENCE_TERMS[keterpaparan_term]
    if keterpaparan == "Tidak diketahui":
        exp_cat, exp_cf = "Open", 1.0
        exp_note = "Keterpaparan tidak diketahui → diasumsikan Open (pedoman SSVC)"

    evidences = [
        Evidence("CVSS", _fmt(float(cvss), 1), cvss_cat, 1.0, "Skor NVD, kategori deterministik"),
        Evidence("EPSS", _fmt(float(epss), 5), epss_cat, 1.0, "Skor FIRST, kategori deterministik"),
        Evidence("Kepentingan", kepentingan, kepentingan, CONFIDENCE_TERMS[kepentingan_term], f"Keyakinan pengguna: {kepentingan_term}"),
        Evidence("Keterpaparan", keterpaparan, exp_cat, exp_cf,
                 exp_note or f"Keyakinan pengguna: {keterpaparan_term}"),
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
    else:
        warnings.append("Tidak ada aturan aktif; CF akhir = 0 (netral).")

    return Result(case_id, evidences, fired, not_fired, steps, cf, warnings)


def competition_rank(values: list[float], tol: float = 1e-9) -> list[int]:
    """Peringkat menurun dengan nilai seri berbagi peringkat (1, 1, 3, ...)."""
    out = []
    for v in values:
        out.append(1 + sum(1 for w in values if w - v > tol))
    return out

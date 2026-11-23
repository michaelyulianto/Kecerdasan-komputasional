"""Perhitungan manual INDEPENDEN (tidak mengimpor engine) memakai bilangan pecahan eksak.

Ditulis ulang langsung dari Tabel I-III dan persamaan (1)-(3) paper, tanpa memakai
kode aplikasi, agar dapat dibandingkan dengan hasil sistem (toleransi 1e-6).
"""
from fractions import Fraction as Fr

W = {"R1": Fr(6, 10), "R2": Fr(4, 10), "R3": Fr(-4, 10), "R4": Fr(8, 10),
     "R5": Fr(-4, 10), "R6": Fr(6, 10), "R7": Fr(-4, 10)}


def rules_for(cvss, epss, exposure):
    c = Fr(str(cvss)); e = Fr(str(epss))
    out = []
    if c >= 9:            out.append("R1")
    elif c >= 7:          out.append("R2")
    elif c < 4:           out.append("R3")
    out.append("R4" if e >= Fr(1, 10) else "R5")
    x = exposure if exposure in ("Open", "Controlled", "Small") else "Open"
    if x == "Open":       out.append("R6")
    elif x == "Small":    out.append("R7")
    return out


def emycin(a, b):
    if a >= 0 and b >= 0:
        return a + b * (1 - a)
    if a < 0 and b < 0:
        return a + b * (1 + a)
    return (a + b) / (1 - min(abs(a), abs(b)))


def manual_cf(cvss, epss, exposure):
    vals = [W[r] * 1 for r in rules_for(cvss, epss, exposure)]  # CF(E) = 1
    acc = vals[0]
    for v in vals[1:]:
        acc = emycin(acc, v)
    return acc

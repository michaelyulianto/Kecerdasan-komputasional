"""Gambar 1: posisi prioritas tiap kasus menurut CVSS saja, EPSS saja, dan CF (dari hasil/hasil_utama.csv)."""
from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
d = pd.read_csv(ROOT / "hasil" / "hasil_utama.csv").sort_values(["rank_cf", "urutan_tampil"])
plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 8})
fig, ax = plt.subplots(figsize=(3.4, 3.6), dpi=300)
y = range(len(d))
specs = [("rank_cvss", "CVSS saja", "#2a78d6", "s", -0.22), ("rank_epss", "EPSS saja", "#eb6834", "^", 0.22),
         ("rank_cf", "CF", "#1baf7a", "o", 0.0)]
for i, (_, r) in enumerate(d.iterrows()):
    xs = [r[sp[0]] for sp in specs]
    ax.plot([min(xs), max(xs)], [i, i], color="#c9c8c3", lw=0.8, zorder=1)
for col, lab, colr, mk, off in specs:
    ax.scatter(d[col], [i + off for i in y], s=22 if mk != "o" else 30, marker=mk, color=colr, label=lab,
               edgecolor="#fcfcfb", linewidth=0.6, zorder=3 if mk == "o" else 2)
ax.set_yticks(list(y)); ax.set_yticklabels(d["kasus"]); ax.invert_yaxis()
ax.set_xticks(range(1, 16)); ax.set_xlim(0.3, 15.7)
ax.set_xlabel("Peringkat (1 = prioritas tertinggi)")
ax.grid(axis="x", color="#e6e5e0", lw=0.5); ax.set_axisbelow(True)
for s in ("top", "right"): ax.spines[s].set_visible(False)
ax.spines["left"].set_color("#8a8984"); ax.spines["bottom"].set_color("#8a8984")
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, handletextpad=0.3, columnspacing=1.0)
fig.tight_layout()
fig.savefig(ROOT / "hasil" / "gambar1_perbandingan_peringkat.png", dpi=300)
print("ok")

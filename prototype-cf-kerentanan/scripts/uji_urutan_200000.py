"""Reproduksi klaim Bagian III.A: 200.000 kombinasi acak tiga nilai CF dalam [-0,8; 0,8]
digabung dalam keenam urutan; laporkan selisih maksimum antar-urutan.
Jalankan dari folder prototype-cf-kerentanan: python scripts/uji_urutan_200000.py [seed]"""
import itertools
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cf_engine import combine  # noqa: E402


def combine_all(values):
    acc = values[0]
    for v in values[1:]:
        acc, _ = combine(acc, v)
    return acc


seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20261123
rnd = random.Random(seed)
mx = 0.0
for _ in range(200_000):
    v = [rnd.uniform(-0.8, 0.8) for _ in range(3)]
    res = [combine_all(list(p)) for p in itertools.permutations(v)]
    mx = max(mx, max(res) - min(res))
print(f"seed={seed} kombinasi=200000 selisih_maksimum={mx:.3e} lulus(<1e-14)={mx < 1e-14}")

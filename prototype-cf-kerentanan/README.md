# Prototipe Prioritisasi Kerentanan Server — Certainty Factor

Prototipe Streamlit untuk paper *Penerapan Certainty Factor untuk Prioritisasi Kerentanan Server Berdasarkan CVSS, EPSS, dan Kondisi Server* (Kelompok 6). Prototipe ini mengikuti rancangan pada Bab III paper revisi.

## Menjalankan

```bash
pip install -r requirements.txt
streamlit run app.py
```

Setelah itu buka http://localhost:8501.

Untuk menjalankan uji perhitungan:

```bash
python -m pytest -q
```

## Isi aplikasi

| Tab | Fungsi |
|---|---|
| Data Masukan | Mengedit pasangan CVE–server langsung di tabel atau lewat unggah/unduh CSV. Bisa juga mengambil CVSS v3.1 dari NVD dan EPSS dari FIRST secara otomatis; tanggal dan versi model EPSS ikut dicatat. |
| Hasil Prioritas | Urutan berdasarkan CF akhir, dibandingkan dengan urutan CVSS saja dan EPSS saja (nilai seri berbagi peringkat), plus penjelasan perubahan posisi dan unduhan CSV. |
| Rincian Perhitungan | Untuk tiap kasus: kategori evidence (Tabel I), aturan aktif dan CF(H,E), aturan yang tidak aktif karena ambang 0,2, serta setiap langkah kombinasi EMYCIN beserta nomor persamaannya. |
| Basis Aturan | Tabel I, II, dan III dari paper. |
| Verifikasi Manual | Mencocokkan hasil sistem dengan perhitungan manual Kasus A/B/C di paper (toleransi 1×10⁻⁶). |

## Struktur

- `cf_engine.py`: penilaian evidence, basis aturan R1–R9, ambang premis 0,2, fungsi kombinasi EMYCIN, dan peringkat. Tidak bergantung pada Streamlit.
- `fetch_scores.py`: klien API NVD (CVSS v3.1) dan FIRST (EPSS).
- `app.py`: antarmuka Streamlit.
- `tests/test_cf_engine.py`: uji contoh paper, batas kategori, ambang, kasus tepi, dan kebebasan urutan kombinasi.

## Catatan

- Kasus A, B, dan C memakai nilai **ilustratif** dari paper. Untuk pengujian, ganti dengan CVE asli lewat fitur "Tambah dari NVD & FIRST".
- API NVD tanpa API key dibatasi jumlah permintaannya. Kalau gagal, tunggu sebentar lalu coba lagi.
- Nilai CF akhir adalah skor dukungan berbasis aturan, **bukan** probabilitas eksploitasi.
- Deploy gratis bisa lewat Streamlit Community Cloud: push folder ini ke GitHub, lalu pilih `app.py` sebagai entry point.

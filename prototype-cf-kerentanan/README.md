# Prototipe Prioritisasi Kerentanan Server — Certainty Factor

Prototipe website untuk paper *Penerapan Certainty Factor untuk Prioritisasi Kerentanan Server Berdasarkan CVSS, EPSS, dan Kondisi Server* (Kelompok 6). Isinya mengikuti Bab III–V paper revisi.

## Menjalankan

```bash
pip install -r requirements.txt
streamlit run app.py
```

Uji otomatis (tanpa internet, memakai server tiruan NVD/FIRST):

```bash
python -m pytest -q
```

## Sumber data

| Data | Sumber | Sifat |
|---|---|---|
| CVSS v3.1 Base Score | NVD CVE API 2.0 (`services.nvd.nist.gov/rest/json/cves/2.0`) | Asli; jarang berubah |
| EPSS | FIRST EPSS API (`api.first.org/data/v1/epss`, dokumentasi: api.first.org/epss) | Asli; diperbarui **setiap hari**, bisa diambil per tanggal |
| Kepentingan & keterpaparan server | Skenario buatan kelompok (`skenario_contoh.csv`) | Simulasi, sesuai batasan paper |

## Alur pemakaian

1. **Data Masukan → Langkah 1:** muat skenario (template atau unggah CSV). CVSS/EPSS boleh kosong.
2. **Langkah 2:** klik *Ambil CVSS & EPSS*. CVE tanpa CVSS v3.1 atau tanpa EPSS ditandai di kolom *Catatan* dan dikeluarkan. Tanpa API key NVD, ada jeda sekitar 6 detik per CVE (batas NVD: 5 permintaan per 30 detik).
3. **Langkah 3:** periksa tabel, lalu klik *Simpan snapshot data bertanggal*. File ini dipakai sebagai data uji resmi supaya pengujian bisa diulang.
4. **Hasil Prioritas:** urutan CF dibandingkan dengan CVSS saja dan EPSS saja.
5. **Rincian Perhitungan:** evidence, aturan aktif, dan langkah kombinasi untuk setiap kasus.
6. **EPSS Dua Tanggal:** analisis tambahan Bab IV.B.
7. **Verifikasi Manual:** hasil sistem dibandingkan dengan hitungan manual di paper.

## Struktur

- `cf_engine.py`: penilaian evidence, aturan R1–R9, ambang 0,2, dan kombinasi EMYCIN.
- `fetch_scores.py`: klien API NVD dan FIRST.
- `pipeline.py`: isi skor, evaluasi, peringkat, dan analisis dua tanggal.
- `app.py`: antarmuka Streamlit.
- `skenario_contoh.csv`: skenario dengan CVE asli dan kondisi server simulasi.
- `contoh_data_uji.csv`: kasus uji logika (nilai buatan, bukan CVE asli).
- `tests/`: unit test dan server tiruan API (`tests/mock_api.py`). Skor dari server tiruan **bukan** data asli.

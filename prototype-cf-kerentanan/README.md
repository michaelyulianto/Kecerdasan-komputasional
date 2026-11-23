# Prototipe Prioritisasi Kerentanan Server — Certainty Factor

Prototipe website untuk paper *Penerapan Certainty Factor untuk Prioritisasi Kerentanan Server Berdasarkan CVSS,
EPSS, dan Keterpaparan Server* (Kelompok 6). **Paper final adalah sumber kebenaran**; kode ini mengikuti
Tabel I–III, persamaan (1)–(3), dan Bagian IV–V paper.

> Nilai CF akhir adalah **skor dukungan berbasis aturan, bukan probabilitas eksploitasi**. Probabilitas eksploitasi
> tetap berasal dari EPSS. Tanpa *ground truth*, perbedaan urutan bukan bukti peningkatan akurasi.

## Ringkasan metode

| Evidence | Kategori | Aturan | CF(Rule) |
|---|---|---|---|
| CVSS v3.1 Base (NVD, metrik Primary) | Critical 9,0–10,0 / High 7,0–8,9 / Medium 4,0–6,9 (netral) / Low 0,1–3,9 | R1 / R2 / – / R3 | 0,6 / 0,4 / – / −0,4 |
| EPSS 30 hari (FIRST) | Tinggi ≥ 0,1 (inklusif) / Rendah < 0,1 | R4 / R5 | 0,8 / −0,4 |
| Keterpaparan server (SSVC System Exposure) | Open / Controlled (netral) / Small; kosong atau tidak diketahui → Open | R6 / – / R7 | 0,6 / – / −0,4 |

- Hipotesis tunggal H: “Pasangan CVE–server perlu ditangani dengan prioritas tinggi.”
- CF(E) = 1,0 untuk semua evidence (kategori deterministik); aturan aktif jika premisnya cocok dan CF(E) > 0,2.
- CF(H,E) = CF(E) × CF(Rule); dukungan digabung dengan fungsi kombinasi EMYCIN:
  (1) CF1 + CF2(1 − CF1) bila keduanya ≥ 0; (2) CF1 + CF2(1 + CF1) bila keduanya < 0;
  (3) (CF1 + CF2)/(1 − min(|CF1|,|CF2|)) bila tandanya berbeda.
- Peringkat kompetisi (1, 1, 3, …): CF sama = **prioritas setara**. Di dalam kelompok setara, urutan tampil memakai
  EPSS mentah lalu CVSS mentah (tie-breaker tampilan saja).

## Menjalankan

Dari folder `prototype-cf-kerentanan`:

```bash
pip install -r requirements.txt
streamlit run app.py                    # aplikasi
python -m pytest -q                     # tes otomatis (tanpa internet; NVD/FIRST memakai server tiruan)
python scripts/evaluasi.py              # angka Bagian V paper -> hasil/
python scripts/uji_urutan_200000.py     # uji 200.000 kombinasi (seed bawaan 20261123)
python scripts/grafik.py                # Gambar 1 paper -> hasil/gambar1_perbandingan_peringkat.png
```

## Data

| Data | Sumber | Keterangan |
|---|---|---|
| CVSS v3.1 Base Score | NVD CVE API 2.0 (`services.nvd.nist.gov/rest/json/cves/2.0`), metrik **Primary** (ditetapkan NVD sendiri, bukan CNA) | Data uji diambil 23 November 2026 |
| EPSS | FIRST EPSS API (`api.first.org/data/v1/epss`) | Skor utama 22 November 2026; pembanding 22 Agustus 2026; model EPSS v5 (v2026.06.15, sejak 15 Juni 2026 menurut halaman FIRST *Get the Data*) |
| Keterpaparan server | Skenario simulasi kelompok (Tabel VI paper) | Bukan hasil pemindaian lingkungan nyata |

- `skenario_contoh.csv`: data uji paper, 15 pasangan CVE–server K01–K15 (14 CVE, 9 server) dengan skor tersimpan.
- `data/`: `kasus_uji.csv`, `nvd_cvss31.csv` (skor, vektor, status NVD), `epss_2026-08-22.csv`, `epss_2026-11-22.csv`,
  `dikecualikan.csv` (3 kandidat tanpa skor Primary NVD), `metadata.json`.
- `contoh_data_uji.csv`: kasus uji logika (nilai buatan, bukan CVE asli), termasuk Kasus A–C paper.
- CVE tanpa CVSS v3.1 Primary NVD atau tanpa EPSS tidak disertakan; tidak ada konversi antarversi CVSS.

## Alur pemakaian

1. **Data Masukan → Langkah 1:** muat skenario contoh (data uji paper), ilustrasi Kasus A–C, atau unggah CSV
   dengan kolom wajib `ID, Server, CVE, Keterpaparan` (kolom `CVSS` dan `EPSS` opsional).
2. **Langkah 2 (opsional):** *Ambil CVSS dan EPSS* dari NVD dan FIRST. Untuk skenario contoh, langkah ini mengganti
   skor tersimpan dengan skor terbaru sehingga hasilnya dapat berbeda dari paper. API key NVD (opsional) tidak disimpan.
3. **Langkah 3:** periksa/edit tabel, lalu simpan snapshot CSV bertanggal.
4. **Hasil Prioritas:** skor CF, peringkat, perbandingan dengan CVSS saja dan EPSS saja, kelompok prioritas setara,
   grafik perbandingan peringkat, dan unduh CSV.
5. **Rincian Perhitungan:** kategori evidence, aturan aktif (CF(E), CF(Rule), CF(H,E)), dan setiap langkah kombinasi
   dengan nomor persamaan.
6. **Analisis EPSS Dua Tanggal:** data tersimpan paper (22 Agustus vs 22 November 2026) atau dua tanggal pilihan dari FIRST.
7. **Basis Aturan**, **Verifikasi Manual** (Kasus A–C), dan **Panduan**.

## Struktur

- `cf_engine.py`: penilaian evidence (Tabel I), aturan R1–R7 (Tabel III), ambang 0,2, CF(E) = 1,0, kombinasi EMYCIN.
- `fetch_scores.py`: klien API NVD (hanya metrik Primary) dan FIRST.
- `pipeline.py`: isi skor, evaluasi, peringkat kompetisi, kelompok prioritas setara, analisis dua tanggal.
- `app.py`: antarmuka Streamlit; `panduan.md`: isi tab Panduan.
- `tests/`: tes paper (`test_paper.py`), tes mesin dan alur data, perhitungan manual independen
  (`manual_reference.py`, pecahan eksak), dan server tiruan API (`mock_api.py`; skornya **bukan** data asli).
- `scripts/`: `evaluasi.py`, `uji_urutan_200000.py`, `grafik.py`; keluaran di `hasil/`.

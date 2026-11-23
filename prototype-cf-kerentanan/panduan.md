## Gambaran umum

Aplikasi ini menjalankan rancangan pada paper: **data masuk → evidence dinilai → aturan dijalankan → CF dihitung → kasus diurutkan → urutan dibandingkan dengan CVSS saja dan EPSS saja.**

Objek yang diurutkan adalah **pasangan CVE–server**. CVE yang sama dapat memperoleh prioritas berbeda apabila berada pada server dengan keterpaparan berbeda (contoh: K08 dan K15 pada skenario contoh).

**Perilaku umum aplikasi**

- Hampir semua tab **menghitung ulang otomatis** setiap kali isi tabel berubah. Ada dua pengecualian yang hanya berjalan ketika tombolnya diklik: **Ambil CVSS dan EPSS** (Data Masukan, Langkah 2) dan **Bandingkan** (tab Analisis EPSS Dua Tanggal).
- Data **hanya tersimpan selama tab peramban terbuka**. Jika halaman dimuat ulang atau ditutup, tabel kembali ke skenario contoh (data uji paper) dan semua editan hilang. Simpan snapshot CSV dan unggah kembali bila diperlukan.
- Setiap orang yang membuka aplikasi memiliki data masing-masing; editan satu orang tidak terlihat oleh orang lain.
- Di Streamlit Community Cloud, aplikasi dapat “tertidur” jika lama tidak dibuka. Klik tombol untuk membangunkannya dan tunggu beberapa saat.

**Asal data**

| Data | Asli atau simulasi | Sumber | Sifat |
|---|---|---|---|
| CVSS v3.1 Base Score | Asli | NVD (NIST) melalui NVD CVE API 2.0 | Jarang berubah |
| EPSS | Asli | FIRST melalui FIRST EPSS API | Diperbarui setiap hari |
| Keterpaparan server (Open/Controlled/Small) | Simulasi | Skenario buatan kelompok (Tabel VI paper) | Tetap sesuai skenario |

Karena EPSS berubah setiap hari, pengujian memakai **snapshot data bertanggal**: data diambil satu kali, tanggalnya dicatat, lalu file yang sama dipakai untuk seluruh pengujian. Skenario contoh sudah berisi snapshot data uji paper: CVSS v3.1 Primary NVD (diambil 23 November 2026) dan EPSS bertanggal 22 November 2026 (model EPSS v5).

## Langkah kerja singkat

1. **Data Masukan → Langkah 1:** muat skenario contoh (data uji paper, skor sudah terisi), atau unggah skenario sendiri lalu klik *Muat file yang diunggah*.
2. **Langkah 2 (opsional untuk skenario contoh):** klik **Ambil CVSS dan EPSS** dan tunggu sampai kotak hijau muncul. Untuk skenario contoh, langkah ini mengganti skor tersimpan dengan skor terbaru sehingga hasilnya dapat berbeda dari paper.
3. **Langkah 3:** periksa tabel. Baris yang kolom *Catatan*-nya berisi “dikeluarkan” tidak ikut dihitung. Klik **Simpan snapshot data bertanggal (CSV)**.
4. **Hasil Prioritas:** baca urutan dan perbedaannya terhadap CVSS saja dan EPSS saja.
5. **Rincian Perhitungan:** pilih satu kasus untuk melihat alasan urutannya.
6. **Analisis EPSS Dua Tanggal:** klik **Pakai data EPSS tersimpan paper**, atau pilih dua tanggal lalu klik **Bandingkan (ambil dari FIRST)**.
7. **Verifikasi Manual:** tunjukkan bahwa hasil sistem sama dengan perhitungan manual di paper.

## Sidebar (panel kiri)

Ringkasan tabel yang sedang aktif. Isinya berubah otomatis setiap kali data berubah.

| Elemen | Arti | Berubah ketika |
|---|---|---|
| **Baris** | Jumlah seluruh baris pada tabel | Baris ditambah atau dihapus, atau data baru dimuat |
| **Dihitung** | Jumlah baris yang memiliki CVSS **dan** EPSS sehingga CF-nya dapat dihitung | Skor diambil, diisi manual, atau dikosongkan |
| **Tanggal skor EPSS** | Tanggal skor EPSS yang dipakai (dari kolom *Tanggal EPSS*). “belum diambil” jika masih kosong | Setelah tombol Ambil diklik |
| **Model EPSS** | Versi model EPSS. Ditulis “disimpulkan dari tanggal” karena API FIRST tidak mengirim nomor versi; versi ditentukan dari tanggal mulai publikasi model menurut halaman FIRST *Get the Data* (v5 sejak 15 Juni 2026, v4 sejak 17 Maret 2025, v3 sejak 7 Maret 2023) | Mengikuti tanggal skor |
| **n baris tidak dihitung** | Klik untuk melihat baris yang dilewati beserta alasannya | Berkurang setelah skor terisi |
| **Sumber data** | Pengingat asal setiap data | Tetap |

Selisih antara **Baris** dan **Dihitung** adalah jumlah kasus yang dikeluarkan, misalnya CVE tanpa CVSS v3.1 Primary NVD. Angka ini perlu dilaporkan pada hasil pengujian.

## Tab Data Masukan

Tab untuk menyiapkan data, terdiri atas tiga langkah.

#### Langkah 1 — Siapkan skenario

| Elemen | Fungsi | Akibat |
|---|---|---|
| **Muat skenario contoh (data uji paper)** | Memuat 15 pasangan CVE–server K01–K15 (14 CVE asli pada 9 server simulasi, Tabel VI–VII paper) beserta skor tersimpan: CVSS v3.1 Primary NVD dan EPSS 22 November 2026 | **Mengganti seluruh tabel.** Editan yang belum disimpan, pesan Langkah 2, dan hasil analisis dua tanggal ikut terhapus |
| **Muat ilustrasi paper (Kasus A–C)** | Memuat tiga kasus pada Bagian III.C paper (nilai ilustratif, bukan CVE asli): A 9,8/0,94/Open → 0,968; B 5,3/0,004/Small → −0,64; C 9,8/0,004/Open → 0,7333 | Mengganti seluruh tabel; dipakai untuk menunjukkan hasil yang sama dengan paper |
| **Unduh template skenario (CSV)** | Mengunduh file skenario contoh untuk diedit di Excel atau Google Sheets | Tidak mengubah apa pun di aplikasi |
| **Kotak unggah** dan **Muat file yang diunggah** | Mengunggah skenario sendiri. Setelah memilih file, tombol *Muat file yang diunggah* **harus** diklik | Mengganti seluruh tabel. Jika kolom wajib kurang, muncul pesan merah dan tabel tidak berubah |

Kolom wajib pada file unggahan: `ID, Server, CVE, Keterpaparan`. Kolom CVSS dan EPSS opsional (boleh tidak ada atau kosong).

Isi kolom Keterpaparan harus ditulis persis: `Open`, `Controlled`, `Small`, atau `Tidak diketahui`. Sel kosong dan `Tidak diketahui` dinilai sebagai **Open** sesuai pedoman SSVC.

#### Langkah 2 — Ambil skor asli

| Elemen | Fungsi |
|---|---|
| **Gunakan EPSS dari tanggal tertentu** | Tidak dicentang: EPSS terbaru. Dicentang: kotak tanggal di bawahnya aktif |
| **Tanggal EPSS** | Tanggal skor EPSS yang diambil. Nonaktif (abu-abu) jika kotak centang mati; tanggal masa depan tidak dapat dipilih |
| **API key NVD (opsional)** | Kosong: jeda sekitar 6 detik per CVE karena NVD membatasi 5 permintaan per 30 detik. Diisi: sekitar 1 detik per CVE. API key dapat diminta gratis di situs NVD |
| **Teks “n kode CVE unik…”** | Jumlah CVE **unik** yang akan diambil beserta perkiraan waktunya. CVE yang sama pada dua server dihitung satu kali |
| **Ambil CVSS dan EPSS** | Mengambil CVSS v3.1 Base metrik Primary dari NVD dan EPSS dari FIRST untuk semua baris berkode CVE asli |
| **Bilah kemajuan** | Menunjukkan CVE yang sedang diambil |
| **Kotak hijau** | Ringkasan hasil, misalnya “CVSS 10 berhasil, EPSS 11 berhasil” |
| **Kotak kuning** | Satu kotak untuk setiap CVE yang gagal, beserta alasannya |
| **Kotak merah** | Koneksi ke NVD atau FIRST gagal sepenuhnya |

Ketika tombol diklik:

- Kolom CVSS, EPSS, Sumber CVSS, Tanggal EPSS, Versi EPSS, Diambil, dan Catatan diisi untuk setiap baris berkode CVE asli. **Nilai yang sebelumnya diisi manual pada baris tersebut ditimpa.**
- Baris dengan kode bukan CVE asli (misalnya `CVE-ILUSTRASI-A`) tidak diubah.
- CVE tanpa CVSS v3.1 Primary NVD (misalnya hanya memiliki skor CNA) atau tanpa EPSS dikosongkan skornya dan kolom *Catatan* diisi alasan serta keterangan “dikeluarkan dari kasus uji”, sesuai batasan paper.
- Jika NVD menolak karena batas permintaan, aplikasi menunggu 30 detik lalu mencoba sekali lagi.
- Baris yang ditambahkan di Langkah 3 sebelum tombol diklik tetap dipertahankan.

#### Langkah 3 — Periksa dan simpan

| Kolom | Isi | Pengaruh ke CF |
|---|---|---|
| **ID** | Kode kasus | Tidak, hanya label |
| **Server** | Nama server | Tidak, hanya label |
| **CVE** | Kode kerentanan | Menentukan skor yang diambil pada Langkah 2 |
| **CVSS v3.1** | 0–10 (kelipatan 0,1) | **Ya**, menentukan kategori Critical/High/Medium/Low |
| **EPSS** | 0–1 | **Ya**, menentukan kategori Tinggi (≥ 0,1) atau Rendah |
| **Keterpaparan** | Open / Controlled / Small / Tidak diketahui | **Ya**: Open → R6, Small → R7, Controlled netral, Tidak diketahui dinilai Open |
| **Sumber CVSS, Tanggal EPSS, Versi EPSS, Diambil, Catatan** | Catatan asal data | Tidak; sebaiknya tidak diubah |

Cara mengedit tabel:

- **Mengubah sel:** klik dua kali sel, ketik, lalu tekan Enter. Kolom pilihan menampilkan daftar pilihan.
- **Menambah baris:** arahkan kursor ke tabel, lalu klik ikon **+** di pojok kanan atas tabel, atau ketik pada baris kosong paling bawah.
- **Menghapus baris:** centang kotak paling kiri pada baris tersebut, lalu tekan Delete atau klik ikon tempat sampah.
- **Ikon lain di pojok kanan atas tabel:** mata (sembunyikan/tampilkan kolom), unduh, kaca pembesar (cari), dan layar penuh.

**Simpan snapshot data bertanggal (CSV)** mengunduh tabel apa adanya sebagai `snapshot_data_<tanggal>.csv`. File ini adalah **data uji resmi**. Untuk mengulang pengujian, unggah file ini pada Langkah 1; jangan mengambil skor ulang karena EPSS akan berbeda.

## Tab Hasil Prioritas

Hasil akhir sistem. Dihitung ulang otomatis setiap kali tabel berubah.

**Empat angka di bagian atas**

| Metrik | Arti |
|---|---|
| **Pasangan dihitung** | Jumlah kasus yang memiliki CVSS dan EPSS |
| **Mendukung prioritas (CF > 0)** | Jumlah kasus yang secara keseluruhan didukung aturan untuk prioritas tinggi |
| **Melemahkan prioritas (CF < 0)** | Jumlah kasus yang secara keseluruhan dilemahkan aturan |
| **Prioritas pertama** | ID dan CVE pada urutan teratas beserta CF-nya. Jika beberapa kasus seri pada urutan 1, ditampilkan ID yang paling awal menurut abjad |

**Tabel Urutan prioritas**

| Kolom | Arti |
|---|---|
| **Urutan** | Peringkat kompetisi berdasarkan CF dari yang terbesar. Nilai seri mendapat nomor yang sama dan nomor berikutnya dilewati; 1, 1, 1, 4 berarti tiga kasus seri pada urutan 1 dan setara prioritasnya. Di dalam kelompok setara, baris ditampilkan menurut EPSS mentah lalu CVSS mentah (tie-breaker tampilan saja, bukan perbedaan prioritas) |
| **ID, Server, CVE** | Identitas pasangan |
| **CF akhir** | Skor dari −1 sampai 1. Bilah menunjukkan posisi skor pada rentang tersebut: penuh mendekati 1, hampir kosong mendekati −1, setengah sekitar 0 |
| **Interpretasi** | Hanya membaca tanda skor: positif “Mendukung”, negatif “Melemahkan”, nol “Netral”. Prioritas ditentukan oleh urutan, bukan oleh label ini |
| **Keterpaparan** | Kategori keterpaparan yang dipakai (Tidak diketahui ditampilkan sebagai Open) |
| **Aturan aktif** | Kode aturan (R1–R7) yang aktif; menjadi dasar penjelasan urutan |
| **CVSS dan Urutan CVSS** | Skor CVSS dan peringkat apabila hanya CVSS yang dipakai |
| **EPSS dan Urutan EPSS** | Skor EPSS dan peringkat apabila hanya EPSS yang dipakai |

**Kelompok prioritas setara** mendaftar kasus dengan CF sama, misalnya “peringkat 1 (CF 0,968): K01, K02”.

**Grafik perbandingan peringkat** menampilkan peringkat setiap kasus menurut CVSS saja, EPSS saja, dan CF (batang lebih pendek = prioritas lebih tinggi).

**Tabel Perbedaan terhadap pengurutan satu skor** menjawab Rumusan Masalah 3:

- **Dibanding CVSS saja:** “sama”, atau misalnya “#10 menjadi #2” yang berarti peringkat 10 menurut CVSS saja menjadi peringkat 2 menurut CF.
- **Dibanding EPSS saja:** perbandingan yang sama terhadap EPSS.
- **Aturan yang menjelaskan:** aturan aktif yang menjadi alasan perbedaan.

**Unduh hasil prioritas (CSV)** menyimpan tabel hasil beserta tanggal proses untuk lampiran laporan.

## Tab Rincian Perhitungan

Jejak perhitungan satu kasus. Gunakan tab ini untuk menjawab pertanyaan “mengapa kasus ini berada pada urutan sekian?”.

| Elemen | Arti |
|---|---|
| **Pilih pasangan CVE–server** | Kasus yang ditampilkan, dengan format `ID · CVE · Server`. Hanya kasus yang dapat dihitung yang tersedia |
| **Kotak kuning** | Peringatan khusus bila ada |
| **CF akhir** | Hasil akhir dengan enam angka di belakang koma |
| **Aturan aktif** | Jumlah aturan yang aktif |
| **Langkah kombinasi** | Jumlah penggunaan rumus kombinasi, yaitu jumlah aturan aktif dikurangi satu |

**Tahap 1 — Penilaian evidence (Tabel I).** Satu baris untuk setiap masukan (CVSS, EPSS, keterpaparan): nilai asli, kategori hasil penggolongan, CF(E), dan keterangan. CF(E) selalu 1,0 karena kategori setiap evidence ditentukan secara deterministik. Jika keterpaparan “Tidak diketahui”, keterangannya menyebut bahwa keterpaparan diasumsikan Open sesuai pedoman SSVC.

**Tahap 2 — Aturan aktif.** Untuk setiap aturan aktif ditampilkan bunyi aturan, CF(E), CF(Rule) beserta istilahnya, dan perhitungan CF(H,E) = CF(E) × CF(Rule). Karena CF(E) = 1,0 selalu lebih besar dari ambang 0,2, setiap aturan yang premisnya cocok pasti aktif.

**Tahap 3 — Kombinasi EMYCIN.** Setiap baris adalah satu langkah penggabungan: aturan yang digabungkan, persamaan yang dipakai, dan perhitungannya.

- Persamaan (1), keduanya positif: CF₁ + CF₂(1 − CF₁)
- Persamaan (2), keduanya negatif: CF₁ + CF₂(1 + CF₁)
- Persamaan (3), tanda berbeda: (CF₁ + CF₂) / (1 − min(|CF₁|, |CF₂|))

## Tab Analisis EPSS Dua Tanggal

Analisis tambahan Bagian IV.B: bagaimana urutan berubah apabila **hanya EPSS** yang berubah.

| Elemen | Fungsi |
|---|---|
| **Tanggal pertama dan kedua** | Dua tanggal yang dibandingkan; bawaannya 22 Agustus 2026 dan 22 November 2026 seperti di paper |
| **Bandingkan (ambil dari FIRST)** | Mengambil EPSS dari FIRST untuk kedua tanggal. Nilai EPSS di tabel Data Masukan **tidak** dipakai; CVSS dan keterpaparan tetap diambil dari tabel |
| **Pakai data EPSS tersimpan paper** | Memakai file EPSS tersimpan 22 Agustus dan 22 November 2026 (tanpa internet) sehingga Tabel IX paper dapat diulang |
| **Kotak kuning** | CVE yang tidak memiliki EPSS pada salah satu tanggal, misalnya CVE yang terbit setelah tanggal pertama |
| **Pasangan dibandingkan** | Jumlah kasus yang berhasil dibandingkan |
| **Berubah posisi** | Jumlah kasus yang peringkatnya berbeda pada kedua tanggal |
| **Melewati ambang 0,1** | Jumlah kasus yang EPSS-nya berpindah kategori |

Kolom tabel:

- **EPSS [tanggal]** dan **CF [tanggal]:** skor pada masing-masing tanggal.
- **Aturan EPSS:** “R4” atau “R5” jika tetap; “R5 → R4” berarti EPSS naik melewati 0,1; “R4 → R5” berarti EPSS turun di bawah 0,1.
- **Urutan [tanggal]:** peringkat CF pada masing-masing tanggal.
- **Urutan EPSS saja [tanggal]:** peringkat bila hanya EPSS yang dipakai, sebagai pembanding.
- **Perubahan posisi:** positif berarti naik peringkat pada tanggal kedua, negatif berarti turun, nol berarti tetap.

Catatan penting:

- **CF hanya berubah jika EPSS melewati 0,1**, karena aturan membaca kategori, bukan angka mentah. Pada data paper hanya K03 dan K06 yang melewati ambang. Jika semua CVE tetap pada sisi yang sama dari 0,1, hasilnya “0 berubah posisi”; itu hasil yang sah, bukan kesalahan.
- Untuk memperoleh perubahan, tambahkan CVE yang EPSS-nya berada di sekitar 0,1. Kandidat dapat dicari melalui `https://api.first.org/data/v1/epss?epss-gt=0.05&epss-lt=0.2&limit=30`.
- Hasil tab ini tidak ikut berubah ketika tabel diedit; klik **Bandingkan** lagi. Hasilnya terhapus jika data baru dimuat pada Langkah 1.

## Tab Basis Aturan

Halaman rujukan yang isinya sama dengan paper dan tidak bergantung pada data.

- **Kalimat pembuka:** aturan aktif hanya jika premisnya cocok dan CF(E) lebih besar dari 0,2 (ambang EMYCIN); setiap aturan memiliki satu premis agar satu evidence tidak dihitung dua kali.
- **Tabel I:** kategori setiap masukan, batas angkanya, dan sumber resminya.
- **Tabel III:** tujuh aturan (R1–R7) beserta bobot dan istilahnya. Kategori netral (CVSS Medium, keterpaparan Controlled) tidak memiliki aturan.
- **Tabel II:** skala istilah CF menurut Sutojo dkk. (2011), dari −1 sampai 1, yang dipakai untuk memilih bobot CF(Rule).
- **Rumus:** tiga persamaan kombinasi EMYCIN.

## Tab Verifikasi Manual

Bukti bahwa sistem menghitung dengan benar (Rumusan Masalah 2).

- Selalu memakai **Kasus A, B, dan C dari paper** dan tidak dipengaruhi data yang dimasukkan.
- **Hasil manual (paper)** dibandingkan dengan **Hasil sistem**.
- **Selisih** ditulis dalam notasi ilmiah: `0.0e+00` berarti sama persis; `1.1e-16` berarti hanya berbeda karena pembulatan bilangan komputer.
- **Status** “Sesuai” jika selisih tidak lebih dari 1 × 10⁻⁶, sesuai kriteria Bagian IV.C.
- Paper menuliskan Kasus C sebagai 0,7333 (dibulatkan); nilai tepatnya 11/15 = 0,733333…, dan nilai tepat itulah yang dibandingkan.
- Perbandingan dengan perhitungan manual independen untuk 15 kasus uji dan 336 kombinasi masukan dijalankan oleh tes otomatis (`python -m pytest -q`).

## Pengaruh perubahan masukan

| Perubahan | Akibat pada perhitungan | Contoh |
|---|---|---|
| CVSS berubah di dalam kategori yang sama | CF tidak berubah; urutan CVSS saja dapat berubah | 9,1 → 9,8: tetap Critical (R1) |
| CVSS melewati batas kategori | Aturan CVSS berganti dan CF berubah | 8,9 → 9,0: R2 (+0,4) menjadi R1 (+0,6); 4,0 → 3,9: tanpa aturan menjadi R3 (−0,4) |
| EPSS berubah tetapi tetap di sisi yang sama dari 0,1 | CF tidak berubah; urutan EPSS saja dapat berubah | 0,5 → 0,99: tetap R4 |
| EPSS melewati 0,1 | R4 dan R5 bertukar; ini perubahan terbesar (+0,8 menjadi −0,4) | 0,12 → 0,08 |
| Keterpaparan berubah | Open: R6 (+0,6); Controlled: tanpa aturan; Small: R7 (−0,4); Tidak diketahui: dianggap Open | K15 (Open) 0,952 dan K08 (Small) 0,8 untuk CVE yang sama |
| ID, Server, Sumber CVSS, atau Catatan berubah | Tidak memengaruhi CF | |
| Baris ditambah atau dihapus | CF kasus lain tidak berubah, tetapi **nomor urut dapat bergeser** karena urutan bersifat relatif | |
| Data baru dimuat pada Langkah 1 | Seluruh tabel diganti; pesan Langkah 2 dan hasil analisis dua tanggal dihapus | |

## Sifat sistem yang perlu dipahami

1. **Aturan membaca kategori, bukan angka mentah.** Perubahan kecil di dalam satu kategori tidak memengaruhi CF. Akibatnya hasil stabil terhadap fluktuasi kecil, tetapi EPSS 0,15 dan 0,99 diperlakukan sama.
2. **Jika EPSS ≥ 0,1, CF pasti positif.** Aturan R4 (+0,8) lebih kuat daripada gabungan aturan negatif lain (R3 dan R7, masing-masing −0,4). Kasus terburuk dengan R4 menghasilkan 0,8 ⊕ (−0,4) ⊕ (−0,4) = 0,4444. CF negatif hanya dapat terjadi jika EPSS < 0,1.

   Sebaliknya, kategorisasi biner EPSS dapat membuat kasus seri (misalnya K05 dengan EPSS 0,99999 dan K06 dengan EPSS 0,10015 sama-sama 0,88) dan membuat CF sangat sensitif di sekitar 0,1.
3. **Label “Mendukung” atau “Melemahkan” hanya menunjukkan tanda.** Prioritas ditentukan oleh urutan CF.
4. **CF bukan probabilitas eksploitasi.** CF 0,98 tidak berarti peluang diserang 98%. Peluang eksploitasi tetap berasal dari EPSS.
5. **Tidak ada ground truth.** Aplikasi membuktikan bahwa perhitungan benar dan alasannya dapat ditelusuri, bukan bahwa urutan CF lebih akurat daripada CVSS atau EPSS.

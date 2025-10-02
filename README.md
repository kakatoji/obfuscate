# obfuscate
# Python Obfuscator & Cython Packer

Alat ini membantu melakukan **obfuscation** (pengacakan kode) pada file Python dan membungkusnya menjadi modul biner `.so` menggunakan **Cython**, sehingga kode lebih sulit dibaca ulang.

> ⚠️ Catatan: Teknik ini hanya **meningkatkan kesulitan** bagi orang yang ingin menyalin kode Anda. Kode Python tetap dapat direverse oleh pihak berpengalaman.

---

## ✨ Fitur
- ✅ Rename semua identifier (variabel, fungsi, kelas) menjadi nama acak.
- ✅ Enkripsi string literal (XOR + Base85).
- ✅ Penambahan control-flow noise.
- ✅ Packing multi-lapis (`marshal + zlib + base85`).
- ✅ Kompilasi ke binary `.so` menggunakan **Cython**.

---

## ⚙️ Instalasi

Pastikan Python dan pip sudah terpasang.

**Termux / Ubuntu:**
```bash
pip install cython setuptools wheel
##JALANKAN
python enc.py bot.py --rename --strings --noise --pack-layers 5

##BUNGKUS DENGAN CYTHON
cythonize -i -3 bot_obf.py


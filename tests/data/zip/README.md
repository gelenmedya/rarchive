ZIP archives made with NanaZip 7.0 (7-Zip engine) from the files in `src/`, one per method:
Deflate, Deflate64, BZip2, LZMA, Zstandard, XZ, PPMd; encrypted: `zipcrypto.zip` (password
`sifre`; 7-Zip refuses non-ASCII ZipCrypto passwords), `aes128.zip` (Deflate) and
`aes256.zip` (LZMA), password `şifre`.

Split sets: `split/bölünmüş.zip.001…003` (NanaZip `-v16k`, numbered parts of one zip);
`spanned/yayılmış.z01, .z02, .zip` (PKWARE spanned layout with disk numbers, converted from
`deflate.zip` by `spanned/mkspanned.py`; NanaZip extracts it byte for byte).

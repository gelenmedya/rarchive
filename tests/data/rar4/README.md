RAR 1.5-4.x test archives.

Everything in this directory except `real/` was generated with the `rars` crate's writer
(0.12.3, Apache-2.0) from the files in `src/` (deterministic pseudo-random text, records, x86-like
code, bitmap, audio, ...), and **each archive was decoded with the official UnRAR (through the
`unrar` crate) to the same bytes before being committed**. The generator was a scratch program, not
part of the repository.

| Archive | What it covers |
|---|---|
| `lz.rar`, `lz-solid.rar`, `rar40.rar` | LZ blocks (plus the PPMd / DELTA blocks the writer chose on its own), solid streams, a stored member, directories, Unicode names |
| `ppmd.rar`, `ppmd-solid.rar`, `ppmd-binary.rar` | PPMd var.H blocks, a model shared across solid members, PPMd on binary data |
| `ppmd-o8-1mb-s64.rar`, `ppmd-o16-1mb-s16.rar`, `ppmd-o64-2mb-s8.rar` | PPMd streams produced by a test encoder (in `src/rar4/ppmd/tests.rs`, driven by `RARCHIVE_EMIT_PPMD=<dir>`) over models of 1-2 MB that the data overflows: the sub-allocator glues free blocks and restarts the model; orders 8, 16, 64; UnRAR decodes them to the same bytes |
| `filters.rar`, `filters-solid.rar` | filters the writer picked on its own (E8E9, DELTA) |
| `flt-e8`, `flt-e8e9`, `flt-itanium`, `flt-rgb`, `flt-rgb2`, `flt-audio`, `flt-audio4`, `flt-delta`, `flt-solid-e8` | one explicitly requested RarVM standard filter each (RGB with two widths and red positions, AUDIO with 2 and 4 channels, E8 across solid members) |
| `v20.rar`, `v20-solid.rar` | RAR 2.0 (unpack version 20), solid |
| `v15.rar`, `v15-solid.rar` | RAR 1.5 (unpack version 15), solid; the directory is marked by its DOS attribute |
| `enc.rar`, `enc-ppmd-solid.rar` | AES-128 data encryption, password `parola ✓ 123` (LZ, and PPMd in a solid stream) |
| `enc-long.rar` | password of more than 28 characters (key material over one SHA-1 block: the original tool's quirk), `bu parola yirmi sekiz karakterden uzundur ve 64 baytı aşar` |
| `enc-headers.rar` | encrypted headers, password `başlık şifresi` |
| `vol-new.part1-3.rar`, `vol-enc.part1-3.rar` | volume sets in the `.partN.rar` style (the writer numbers volumes old style; the files were renamed after UnRAR had checked the set); `vol-enc`: password `parça şifresi` |
| `vol-old.rar/.r00`, `vol-enc-headers.rar/.r00` | volume sets in the `.rar/.r00` style, the second with encrypted headers (`parça şifresi`) |

`real/` holds archives made by historical RAR releases, see `real/PROVENANCE.md`.

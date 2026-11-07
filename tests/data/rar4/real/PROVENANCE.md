Archives made by historical RAR / WinRAR releases (RAR 1.54, 2.50, 3.00, 4.20), taken from the test
fixtures of the `rars` crate 0.12.3 (https://crates.io/crates/rars, Apache-2.0), which in turn
copied them from its specification repository's `fixtures/` sets. They are used here because
they exercise decoder paths that archives written by `rars` do not reach: every standard RarVM
filter (E8, E8E9, ITANIUM, DELTA, RGB, AUDIO), PPMd streams with embedded LZ matches and VM
records, a solid E8 filter across members, DELTA with 64 channels, RAR 2.0 audio, RAR 1.5,
old and new volume naming, and encryption made by real WinRAR.

Every member is checked against the CRC32 stored in the archive; where the original payload
is known it is kept in `src/` and compared byte for byte.

| File | What it is |
|---|---|
| `rarvm_*_rar300.rar` | one member each, RAR 3.00, one standard filter per archive |
| `ppmd_lz_match_rar300.rar`, `ppmd_lz_repeat_rar3.cbr` | PPMd with escape-coded LZ matches / repeats |
| `ppmd_lorem_rar300.rar`, `ppmd_solid_rar300.rar` | PPMd text, PPMd model reused across solid members |
| `ppmd_embedded_vm_filter.rar` | a VM filter record inside a PPMd stream |
| `solid_e8_filter_member_offset.rar` | solid, E8 filter, file offsets across members |
| `delta_64_channels.rar` | DELTA filter with R0 = 64 |
| `ext_time_rar420.rar` | WinRAR 4.20 extended time record |
| `readme_154_normal.rar` | RAR 1.54 (unpack version 15) |
| `AUDIO.RAR`, `SOLID.RAR`, `unpack20_keep_tables.rar` | RAR 2.50 (unpack version 20) |
| `multivol_oldnaming_rar300.*`, `multivol_newnaming_rar300.part0N.rar` | RAR 3.00 volumes, `.rar/.r00` and `.partNN.rar` |
| `per_file_rar300_password.rar`, `header_rar300_password.rar`, `header_rar420_password.rar` | password `password`, member `hello.txt` (CRC32 a538535e) |
| `rar4_junrar_*.rar` | from the junrar project's tests: passwords `junrar` and `test` |
| `rar4_mixed_visible_names_password.rar` | WinRAR 4.20: stored + encrypted members, password `known-pass` |

**Not in the repository** (third-party files). To run `tests/rar4_real.rs`, put the fixtures of the
`rars` crate 0.12.3 listed above in this folder; without them those tests skip.

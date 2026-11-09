# rarchive research report (pure-Rust RAR library + CLI)

Date: 2026-11-06. Status: research phase. No rarchive code has been written yet. This document is a design report.

Reading rules (clean-room): the official UnRAR C++ source, `unrar_sys`, `unrar-rs`, `weaver-unrar` and the C++ parts of `third_party/unrar` were NOT opened. Sources read: the RARLAB technote (through WebFetch), the `rars` 0.12.3 (Apache-2.0) source, and, for `compcol` 0.7.8 and `rar-codec` 0.1.9, only header/structure-level greps. UnRAR C++ was only run as a timing baseline (through the harness).

Confidence markers: **[measured]** measured in this session, **[source]** taken from a source that was read, **[estimate]** my own estimate or inference, to be verified.

---

## 0. Executive summary

1. The formats that matter in practice are **RAR5 (v0)** and **RAR3/4 (RAR 2.9-4.x)**. RAR7 (algorithm version 1) is an extension of RAR5 as a format; the main difference is the large dictionary (in the encoding). RAR 1.5/2.0 matter only for old archives; they come last.
2. The technote describes only the **container** (headers, vint, encryption fields, hash records); it does **not describe the compression algorithm (Huffman/LZ/filter bit layout)**. The gap is filled by `rars` (Apache-2.0), libarchive `archive_read_support_format_rar5.c` (BSD-2) and `compcol` (MIT).
3. The existing pure-Rust decoders (rars, rar-codec) are ~1.9x slower than UnRAR C++ on a single thread. **Why they are slow is clear from the code**: for every symbol they re-read a 3-byte slice from the bit position, the output is copied twice (pending -> VecDeque history -> sink), a budget check on every push, a cancel/progress check on every symbol. So it is not "Rust is slow", it is "these decoders were not written to be fast".
4. Profile [measured]: in the solid archive, 400 MB of output = 60.5 M literals + 24.7 M matches (average 13.8 bytes) ~ **85 M commands**, ~10.2 bits per command. The rars decoder function spends ~1.4-1.6 s (~17-19 ns/command), UnRAR end to end 0.94 s (~11 ns/command). Match copying is negligible (ablation: within noise); table building is 2-3%; what remains is the **symbol-decoding latency chain** and **overhead outside the decoder (20-30%)**.
5. Beating UnRAR is realistic: (a) a 64-bit bit buffer + preprocessed table entries, targeting ~5-7 ns per command on a single thread [estimate] => solid decoding in ~0.5-0.7 s; (b) writing the output directly into the final buffer and removing the copies; (c) moving CRC/BLAKE2sp/filter/write work to separate threads; (d) parallelizing the Huffman/command parsing stage (which is data-independent!) across blocks, **even in a solid archive** (section 4.9, the most important idea in this report). For non-solid, per-file parallelism already beats UnRAR (rars parallel 0.60 s vs UnRAR 1.06 s).
6. **Critical warning:** the benchmark archives are archives produced by the `rars` encoder (level 1). The symbol distribution, block size and filter use of real WinRAR output will differ. Without real WinRAR archives the claim "faster than UnRAR" is not proven (section 6.4).
7. Recommended next step: a **fast-core spike** (RAR5 LZ decoder, for solid and non-solid alike, with its own 64-bit bit reader and a single-pass output buffer instead of `rars`'s block parser) and finding 3-5 real WinRAR archives. Exit criterion: in the same harness, solid archive decoding <= 0.9 s (UnRAR 0.94 s), single-thread, at the decode-function level.

---

## 1. The format landscape

### 1.1 Versions and order of importance

| Version | Era | Algorithm | Importance today |
|---|---|---|---|
| RAR 1.3 / 1.5 | ~1993-1997 | LZ + Huffman (simple) | Very low (old archives) |
| RAR 2.x | 1996-2002 | LZ + Huffman, multichannel "audio" mode | Low |
| RAR 2.9-4.x ("RAR3") | 2002-2013 | LZ+Huffman **or PPMd (var.H)**, **RAR VM filters**, AES-128 | **High**: the large majority of old archives on the internet; shares from adaptation/game/warez/archive sites |
| RAR 5.0-6.x | 2013- | LZ+Huffman, new filters (DELTA/E8/E8E9/ARM), NO PPMd and NO VM | **High**: the new default, WinRAR 5+ output |
| RAR 7.0 | 2024 | RAR5 + algorithm version 1 (larger dictionary) | Growing; when WinRAR 7 users enable a large dictionary |

Why: RAR3 is a large library of old archives; RAR5 has been the default since 2013. Both are required for a file manager; RAR5 first (simpler, easier target for speed, a single Huffman decoder); in RAR3, PPMd and the VM standard filters are extra work.

### 1.2 Feature matrix

| Feature | RAR 1.5 | RAR 2.x | RAR3/4 | RAR5 | RAR7 |
|---|---|---|---|---|---|
| Signature | `Rar!\x1a\x07\x00` (7 bytes) | same | same | `Rar!\x1a\x07\x01\x00` (8 bytes) [source: technote] | same |
| Solid | yes | yes | yes | yes (bit 6 in the file header) | yes |
| Encryption | simple XOR-like | block cipher (custom) | AES-128-CBC, KDF SHA-1 x 0x40000 rounds (262144) [source: present in rars crypto/rar30.rs; details to be verified] | **AES-256-CBC, PBKDF2-HMAC-SHA256** | same |
| Header encryption (-hp) | no | no | yes | yes (type 4 header) | yes |
| Multi-volume | yes | yes | yes (.partN.rar / .rNN) | yes (main header bit 0/1, header flags 0x8/0x10) | yes |
| Recovery record | no | no | yes (RR block 0x78 / service "RR") | yes ("RR" service header, Reed-Solomon) | yes |
| Quick open | no | no | no | **yes** ("QO" service; locator record) | yes |
| Service headers | - | - | 0x7A "new sub" (CMT, ACL, STM...) | type 3 (CMT, QO, ACL, STM, RR) | same |
| Hash | CRC32 (CRC16 header) | CRC32 | CRC32 (header CRC16 = low 16 bits of CRC32) | **CRC32 (in header) + optional BLAKE2sp (extra record 0x02)** | same |
| Filters | - | audio (multichannel) | RAR VM (standard: E8, E8E9, ITANIUM, RGB, AUDIO, DELTA) | **DELTA, E8, E8E9, ARM** (fixed, no VM) | same |
| Dictionary | 64 KB | 64 KB-1 MB (64K-4M encoded in the archive) | 64 KB - 4 MB | 128 KB x 2^N, **technote: up to 4 GB (N<=15)** | **encodable up to 64 GB (N<=19; theoretical 23 = 1 TB)** [source: technote] |
| File name | OEM | OEM | OEM + Unicode extra | UTF-8 | UTF-8 |

Notes:
- Practical RAR5 dictionary limits: WinRAR 5/6 typically 1 GB (64-bit), 256 MB (32-bit); RAR7 up to 4 GB [estimate, to be verified against WinRAR versions]. The technote says "real implementations may set a lower limit".
- **What changes in RAR7** (technote, the "compression information" vint): bits 0-5 algorithm version (0 or 1; 1 requires RAR 7.0+), bits 10-14 dictionary power (values above 15 can occur in v1), **bits 15-19 v1 only: intermediate dictionary sizes** (`size + size*value/32`), **bit 20: v1 encoding but the data is v0** (used to enlarge the dictionary when a v1 file is added to a v0 solid stream). Also [source: rars `table_length_count(algorithm_version)`] in v1 the **distance table has 80 symbols instead of 64** (for distances above 4 GB); the table length differs for algorithm version 1. To verify: whether v1 has any other change (e.g. in the length/distance coding). rars has an `algorithm_version` parameter; this will be settled by reading the source (first phase).
- RAR3 encryption details and RAR5 KDF details are in 1.3 below.

### 1.3 RAR5 encryption / KDF

- Technote: encryption version 0 (AES-256), flag 0x1 = password check data (12 bytes), 0x2 = "tweaked checksums" (the file's CRC32/hashes are transformed with the key), KDF count = log2(PBKDF2 iterations), salt 16 bytes, IV 16 bytes. **The PRF name is not in the technote.** Additional source: rars `src/crypto/rar50.rs` and libarchive: PBKDF2-HMAC-SHA256; default log2 = 15 (32768 iterations) [source: rars `crypto/rar50.rs` lines 25-26]. `key` and `hash_key` are two separate 32-byte derivations (rars `Key{key, hash_key}`); the password check value is derived from an additional 16/32 rounds of the same PBKDF2 stream [information: recalled from 7-Zip/libarchive documentation; to be verified against the rars code].
- Header encryption: every header is 16-byte IV + AES-CBC (padded to a 16-byte multiple).
- Cost [estimate]: 32768 x 2 SHA-256 compressions ~ a few ms with SHA-NI, ~20-40 ms without SHA-NI. The `sha2` crate picks SHA-NI automatically through cpufeatures. Not a problem; **but** each file can have a different salt (the file encryption record carries a salt; without -hp, files are encrypted with different salts) -> in an encrypted archive with many files the KDF is multiplied by the number of files: 10k files x 5 ms = 50 s! Solution: a KDF cache for the same (password, salt, log2) triple; for different salts, run the KDF on parallel threads. (WinRAR mostly uses a single salt per archive; to be verified with a real archive.)
- AES-CBC **decryption** can be parallelized (each block is XORed only with the previous ciphertext block); with AES-NI, an 8-block pipeline; with the `aes` crate (AES-NI automatic) 2-6 GB/s [estimate]. Decryption can run as a separate stage before the decoder thread.

### 1.4 RAR3/4 encryption (summary, high level)
AES-128-CBC; the key and IV are derived by running SHA-1 for 0x40000 rounds over password (UTF-16LE) + 8-byte salt + 3-byte counter (the IV comes from bytes taken at specific rounds). SHA-NI exists for SHA-1; even ~262144 compressions are ~50-100 ms per file [estimate] -> same caching logic.

### 1.5 RAR3/4 high-level structure
- Block header: CRC16 (2) + type (1) + flags (2) + size (2) [+ ADD_SIZE (4) with flag 0x8000]. Types: 0x72 marker, 0x73 main, 0x74 file, 0x75 old comment, 0x76 AV, 0x77 old sub, 0x78 protect (RR), 0x79 sign, 0x7A new sub (service), 0x7B end of archive.
- File header flags: 0x01 continued from the previous part, 0x02 continues in the next, 0x04 password, 0x10 solid, 0xE0 dictionary size (0xE0 = directory), 0x100 large file (64-bit), 0x200 Unicode name, 0x400 salt, 0x800 version, 0x1000 extra time. Packing method 0x30 (store) - 0x35 (best), unpack version 15/20/26/29/36 [rars `rar15_40.rs` + general knowledge; to be verified].
- Decoder: **main Huffman (299 symbols), distance (60), low distance (17), length (28)** + PPMd var.H (selection bit at the start of the block) + VM filters (a standard filter is recognized by CRC + length; an arbitrary VM program is rare in practice).
- PPMd var.H: it differs in range coder details from 7-Zip's PPMd7 family; `rars/src/codec/ppmd.rs` (2418 lines) and `rar-codec/src/ppmd7.rs` (1743 lines) can be read for reference (Apache-2.0). PPMd is a very slow model: single-threaded, memory-bound (memory allocator/tree walking). **It is hard to beat UnRAR on PPMd archives**; the goal should be "not slower than UnRAR" (equal), because speed is mostly branches of the model update and cache misses. What will make a difference here is memory layout (a u32-indexed arena, structure alignment) and branch reduction.

---

## 2. The RAR5 decoding pipeline

### 2.1 Container (technote, complete)
For the full summary of the technote see the source: https://www.rarlab.com/technote.htm. Core points:
- vint (7 data bits + continuation bit, little-endian, at most 10 bytes); other integers are LE.
- General block: CRC32 (from the header size up to the extra area) + header size (vint, **at most 3 bytes = 2 MB**) + type (1 main, 2 file, 3 service, 4 archive encryption, 5 end) + flags (0x1 extra area present, 0x2 data area present, 0x4 skip if unknown, 0x8 continued from the previous volume, 0x10 continues in the next, 0x20 depends on a previous block, 0x40 preserve) [+ extra area size] [+ data size].
- Main header: flags (0x1 volume, 0x2 volume number present, 0x4 **solid**, 0x8 recovery, 0x10 locked); extra record 0x01 **locator** (quick-open and recovery offsets), 0x02 metadata.
- File/service header: flags (directory, unix mtime, CRC32 present, **size unknown**), unpacked size, attributes, mtime, CRC32, **compression information vint** (see 1.2), host OS, name. Extra records: 0x01 encryption, 0x02 hash (BLAKE2sp, 32 bytes), 0x03 time, 0x04 version, 0x05 redirection (symlink/junction/hardlink/copy), 0x06 unix owner, 0x07 service data.
- Compression information: bits 0-5 algorithm version, bit 6 solid, bits 7-9 method (0 = store, 1-5), bits 10-14 dictionary power, 15-19 + 20 v1 only.
- Service headers: CMT (comment, uncompressed), QO (quick open: structures cached with CRCs; **security note: showing names from QO and reading them from the header at extraction should give the same result**), ACL, STM, RR.
- File name safety: `/` is the separator, `\` is invalid on Windows; on Unix, bytes that cannot be converted are mapped to the private-use range U+E080-U+E0FF.

### 2.2 Compressed data (NOT in the technote; from rars + libarchive + compcol)
Source files: `rars-0.12.3/src/codec/rar50.rs` (lines 143-380 blocks/tables, 963-1120 decode loop, 1969-2045 slot functions), `compcol-0.7.8/src/rar5/decoder.rs`, libarchive `archive_read_support_format_rar5.c` (not read in this session; indirectly through the rars/compcol documentation).

**Block structure** [source: rars `parse_compressed_block`, details at lines 143-200]: the bit stream is **MSB-first** (most significant bit first). Each compressed block: 1 flag byte (low bits: number of bits used in the last byte minus 1; next fields: number of size bytes minus 1; the "last block" bit; the "tables present" bit), 1 checksum byte (XOR with a constant), 1-3 bytes of block size, then the payload. If tables are absent, they are **inherited** from the previous block (solid and across blocks).

**Tables** [source: rars `read_table_lengths`]: first a 20-symbol "level" table (each code length is 4 bits; value 15 followed by a 4-bit count = zero-run escape), then, with this level Huffman, the code lengths of the following alphabets in a single stream: **main (306)**, **distance (64; 80 in v1)**, **alignment (16)**, **length (44)**. Level symbols 0-15 = direct length; 16/17 = repeat the previous length (3+3 bits / 11+7 bits); 18/19 = repeat zeros (3+3 bits / 11+7 bits) [general knowledge, to be verified against the rars code]. The longest code is 15 bits. Incomplete trees are accepted (unused alphabets).

**Main alphabet layout** [source: rars decode loop]: 0-255 literal; 256 filter; 257 "repeat the last length with the same rep[0]"; 258-261 match with distance rep[0..3] (length separately from the length table); 262-305 length slot (44), followed by the distance slot.

**Length slot -> length**: slot < 8: `slot + 2`, no extra bits. Otherwise `nbit = (slot>>2) - 1`, `length = (((4 | (slot&3)) << nbit) | extra) + 2`.
**Distance slot -> distance**: slot < 4: `slot + 1`; otherwise `nbit = (slot-2)>>1`, `distance = ((2 | (slot&1)) << nbit | extra) + 1` (rars `distance_from_slot_parts`). **Length bonus**: distance > 0x100: +1, > 0x2000: +1, > 0x40000: +1 (new matches only). **Alignment mode**: if the distance nbit >= 4 and the alignment table is "not flat", the upper `nbit-4` bits are taken directly and the low 4 bits come from the alignment Huffman (rars `align_mode`).
**Rep state**: a 4-entry LRU `reps[4]` + `last_length`; a new match does `reps.rotate_right(1)`; a rep match does `reps[..=i].rotate_right(1)`.
**Filter record (256)**: [source: rars `read_filter`] start offset and length (2-bit n, followed by (n+1) bytes LE), type (3 bits: 0 DELTA, 1 E8, 2 E8E9, 3 ARM), channel count for DELTA (5 bits +1). The range is **relative to the output decoded so far**. rars also uses UnRAR's `MAX_FILTER_BLOCK_SIZE` = 0x400000 (4 MiB) limit; source: rars comment (lines 35-41). Accept this as a format limit, but the filter count limit (8192) should be our own defensive limit.
**Carrying solid state**: the window (the last `dict` bytes), `reps`, `last_length`, **the Huffman tables of the last block** (used if the next block says "no tables"); the filter list is reset at a file boundary. The x86 filters compute **file-relative** addresses: in a solid stream the start offset of each member must be known (compcol `add_file_boundary` handles this explicitly).
**End of file**: do blocks not cross the file boundary? The rars code finishes with `block.header.is_last || output.written() >= output_size`; that is, a file = one or more blocks, with the "last" bit in the last block. To be verified on a real WinRAR archive (section 4.9 depends on this).

### 2.3 What the technote skips and what fills the gap
| Skipped | Source that fills it |
|---|---|
| Block header, tables, symbol layout, slot formulas, filter bit layout | rars `codec/rar50.rs`; compcol `rar5/`; libarchive rar5.c |
| PRF (PBKDF2-HMAC-SHA256), password check computation, "tweaked checksum" | rars `crypto/rar50.rs`; libarchive |
| The entire RAR3/4 format | rars `rar15_40*`, `codec/rar29*`, `rarvm*`; rar-codec; libarchive `archive_read_support_format_rar.c` |
| Recovery record (Reed-Solomon) format | rars `recovery/rar5`; (not needed for v1, but listed) |
| RAR7 v1 differences | the technote has the bit layout; for the algorithm details, the use of `algorithm_version` in rars |

---

## 3. Profile: where does the time go?

### 3.1 Method and limits
- There is no profiler on Windows (no `samply`, `perf`, `xperf`; `wpr` exists but needs admin; UAC was not triggered -> not used). So: (a) counters and timers were added to a **copy** of `rars` 0.12.3 (`rars-prof`; the original in the registry was not touched), (b) ablation (replacing the match copy with zero-filling; since symbol parsing is independent of the data, the decoding flow is not broken), (c) independent micro-measurements.
- Tools: `rarprof` (Cargo project; output `target\rarprof`).
- **Measurement noise is large**: an IDE, Spotify etc. were running on the machine; the same job varied between 1.77 s and 2.3 s. The numbers below are "at least 3 runs, the best where possible" but can vary by ±15%. When deciding, the ratio/structure matters, not the absolute value.

### 3.2 Harness re-measurement (this session, `bench.exe`, best of 3) [measured]
| archive | UnRAR C++ | rars 1 thread | rars parallel | rar-codec |
|---|---|---|---|---|
| normal (520 files, 114 MB) | 1.06 s (377 MB/s) | 1.78 s (225) | 0.60 s (671) | 1.77 s (226) |
| solid (109 MB) | 0.94 s (427 MB/s) | 1.77 s (226) | 1.74 s (230) | 1.73 s (232) |

(An earlier run measured 1.26 / 1.12 s for UnRAR on a busier machine; the ratio, about 1.7-1.9×, was the same.)

### 3.3 Archive content statistics (rars-prof counters) [measured]
| | solid | normal |
|---|---|---|
| Compressed block count | 6367 (all with tables) | 6422 (all with tables) |
| Packed bytes | 108.6 MB | 114.5 MB |
| Literal count | 60.5 M | 64.2 M |
| New match (count / bytes) | 14.8 M / 180 MB (avg. 12.2 B) | 16.3 M / 205 MB (avg. 12.6 B) |
| Rep match (count / bytes) | 9.9 M / 160 MB (avg. 16.2 B) | 7.7 M / 131 MB (avg. 17.1 B) |
| Filter | 0 | 943 filters, 40.5 MB |
| distance <= 8 | 269 K (1.1% of matches) | 361 K |
| distance > 1 MiB | 0 | 0 |

Inferences:
- **71% of the commands are literals**, but 15% of the output is literal. Bit rate: ~10.2 bits/command. Average block: ~17 KB packed, ~63 KB output (specific to the rars encoder; may differ in WinRAR).
- There are NO filters in the solid archive (rars may not search for filters in solid mode). For real executables/DLLs, WinRAR uses E8/E8E9, solid included.
- There is no distance > 1 MiB at all: rars level 1 uses a small window; WinRAR uses 32 MB+ (the default RAR5 dictionary is high, ~32-64 MB [estimate]) -> **cache behavior** (far distance = L2/L3 miss) will be worse in real archives. The benchmark archive does not reflect this.

### 3.4 Time distribution (rars, solid, single thread) [measured, per run]
| Component | Time | Share | Note |
|---|---|---|---|
| Total wall clock (extract_to, null/CRC sink) | 1.8-2.2 s | 100% | variation between runs |
| `decode_member...` function total | 1.39-1.64 s | ~70-75% | symbol decoding + literal push + match + memory growth |
| - table building (6367 blocks) | 0.04-0.05 s | ~2-3% | ~7 µs per block |
| - reading the block payload (copy) | 0.007-0.010 s | <1% | |
| - restoring history (solid) | 0.005-0.006 s | <1% | |
| - filter application | 0 (solid) / 0.03 (normal) | <2% | 40 MB E8 |
| - match copy (ablation) | within noise (<~10%) | small | average match 13.8 B |
| **Outside the decoder** (member loop, source reading, `Box<dyn Write>` copy, Vec lifecycle/page faults, CRC verification) | ~0.4-0.6 s | **~20-30%** | hypothesis: a fresh Vec for 400 MB = page faults + zeroing + freeing |
| CRC32 (crc32fast, all 400 MB) | ~0.01 s | ~0 | 45-55 GB/s with a warm cache (looks very high; negligible anyway) |
| Source file read (400 MB, warm cache) | 0.10-0.28 s | | not for the archive, for comparison |
| Disk write (400 MB, sync included) | ~0.32 s (~1.2 GB/s) | | single measurement, Defender/NTFS effect included |

Cost per command: the rars decoder ~17-19 ns/command (≈75-85 cycles @ ~4.5 GHz) [computation: 1.5 s / 85.2 M commands]. UnRAR end to end ~11 ns/command. This number shows that the "Huffman decoding + bit reading + literal writing" region dominates, because both match copying and table building are small.

### 3.5 Structural slowness found in the rars code [source: rar50.rs]
1. **BitReader**: it keeps `bit_pos` (in bits); every `peek15` recomputes the byte position/bit offset, `input.get(byte_pos..)` + a 3-byte `match` slice (a branch) -> on every symbol 1 memory load + a separate byte assembly. `read_bits` additionally has a `NeedMoreInput` bounds check + a 5-byte `match`.
2. **Huffman table**: a 10-bit fast table (u32 entry = 4 KB) + a **loop search** by length for 11-15 bit codes; symbols are in a `usize` (8-byte) array. There is no preprocessed "base value + extra bit count": the extra tables for length/distance, `length_slot_extra_bits` and `slot_to_length` computations are done after the symbol.
3. **Double copy**: literals and matches are written into `pending` (64 KB), handed to the sink with `flush`, AND copied into `history` (a VecDeque) with `extend_admitted(iter)` (a byte-by-byte iterator!). This is the streaming path; the "buffer" path decodes the whole member into a Vec and then filters (it inflates memory).
4. A budget/allowance check on every `try_push`; a `poller.check_codec` (cancel/progress) call on every command.
5. Parallelism only **per file** (non-solid).
This is why it runs at 225 MB/s; rar-codec is similar (226 MB/s): `peek32` accumulates with a byte-by-byte `acc = (acc<<8)|b` loop; the window is a power-of-two ring Vec (good), but bit reading is slow. compcol: 9-bit primary table + 16-bit peek, a power-of-two ring window `vec![0; ws]` (only the default 1 MiB; allocation cost with a large dictionary), a `pending` output buffer; not measured in this session.

### 3.6 Memory behavior
- rars: VecDeque history (grows with the file size, limit `dict + dict/4`), `pending` 64 KB, history is carried over in solid; on the non-streaming path the whole member output is one Vec (as much RAM as the output size for a large file).
- UnRAR (general knowledge, source not looked at): allocates the dictionary size. Risk of a 4 GB commit with a 4 GB dictionary archive; our goal: a window that **grows as output is written** (section 6).
- Decoder working set: main table 306 symbols + distance 64 + length 44 + alignment 16; ~8-16 KB for the fast tables: fits in L1 (32-48 KB); the window + input stream determine the L2/L3 load.

---

## 4. Speed techniques (RAR5-focused)

For each item: expected effect [estimate], source/idea.

### 4.1 64-bit bit buffer with branchless refill
For an MSB-first stream, a left-aligned 64-bit buffer: `buf |= be64(ptr) >> nbits; ptr += (63 - nbits) >> 3; nbits |= 56;` (Fabian Giesen, "Reading bits in far too many ways", variant 4; libdeflate `bitbuf`/`REFILL_BITS_BRANCHLESS`). All code + extra bits (<= 15 + 24 + 15 + 31 bits...) may not fit in a single refill: at most 1-2 refills per command. A safe slow path at the end of the input (8 bytes of zero padding or a separate loop for the tail). Effect: removes ~40-60% of the bit reading/symbol cost in rars [estimate].

### 4.2 Table design
- **Preprocessed 32-bit entry** (libdeflate `decode_results`): entry = {class (literal/rep/length/filter/end), code length, extra bit count, base value}. The base + extra bit count for length and distance are embedded in the table -> no branch/arithmetic after the symbol.
- Primary table: 11-12 bits for main (2^11 x 4 B = 8 KB), 8-9 bits for distance, 8 bits for length; a subtable for long codes (libdeflate main table 11 bits, subtable; zstd huff0 11-12 bits). The distance base value with 31 extra bits does not fit in 32 bits -> the distance entry is u64 or two separate arrays (base, nbit).
- **Multi-symbol (double literal) entry** (zstd huff0 X2, Charles Bloom's Huffman series): if two short literals total <= the primary bit count, two literals in a single entry. In this data 71% of the commands are literals -> literal runs average ~2.4 -> a gain of 15-30% [estimate]. **Caution:** since there is ~63 KB of output per block, table building time matters; build the double-symbol table only if the block is large enough (e.g. packed > 16 KB), or build it lazily. Measurement: table building is currently 2-3%; if it becomes 4x more expensive, 8-12% => borderline.
- Table building speed: counting-sort filling (canonical, `rars`-like scatter) + `memset`-like region filling; can be brought down from 7 µs/block to 2-3 µs [estimate].

### 4.3 Fast literal runs
Main loop: while decoding a command, if literals are consecutive, decode 2-3 consecutive literals with a single refill (64 bits ~ provided 5-6 literal bits), and do a single 8-byte write (with a tail slack that allows writing over). libdeflate: a single write per literal + "load the next entry in advance" (entry prefetch) -> avoids load latency (`entry = table[bitbuf & mask]`: the next round's load overlaps with the processing of the current command). This "breaking the write-read dependency" is the real gain on a single thread.

### 4.4 Match copy
Measurement: average match 13.8 B, distance<=8 only 1.1% -> fast path: if distance >= 16, a loop copying 16 B (SSE2) at a time, as long as the length; with **tail slack** allowing writing past the end (>= 64 B extra at the end of the window/output). distance < 16: pattern broadcasting (in an 8 B register) or repeated doubling copy (rars's "doubling" technique is right, but a special path for 1 B/2 B/4 B: distance 1 = byte fill). Effect: small overall (ablation: <10%), but significant for large files (long average match). **In a real WinRAR archive** matches are longer/the compression ratio is higher -> the copy share rises; in text/repetitive data (e.g. a zero-filled VM disk) the match is very long: a large memory-bound copy; here the difference from UnRAR depends on the quality of `memmove`.

### 4.5 Window: ring or flat output buffer?
- **Non-solid and file <= dictionary**: window = output buffer. Decode the output directly into the final buffer (set aside for writing); no second copy. rars does not do this (pending + history).
- **Large file / solid**: above the `dict` size a power-of-two ring + a "repeating" tail slack at the end. Alternative: a large flat buffer + `memmove` per slice (the zstd "prefix" approach): expensive if dict is large; the ring is preferred. Match copy wrap check in the ring: if distance <= position, a no-wrap fast path (the majority), otherwise a slow path (<1% of matches [estimate]).
- **Growth**: the window should grow as output is written (doubling, up to `dict`); without making a 4 GB virtual allocation (Windows commit charge) for a 4 GB dictionary archive. Safety limit: the `max_window` given by the caller.
- The slices handed to the sink come from the window (<= 2 slices); for hash/write, a **buffer pool** + `Arc<[u8]>` handover instead of copies.

### 4.6 Bounds checking and `unsafe`
- The first version is fully safe: tables are fixed-size arrays (`[u32; 1<<11]`) and indices are bounded by a mask -> the compiler removes the check; for the input, inside a "safe region" loop (`while in_pos + 16 <= len && out_pos + SLACK <= cap`) the slice conversion is done once with `&[u8; 16]`/`try_into`.
- `unsafe` only if justified by measurement: (1) output writing/reading with `get_unchecked` in the fast loop, (2) 16/32 B wide copy (a wrapped `ptr::copy_nonoverlapping`). A module limited to 3 functions (`fastcopy`), `#![forbid(unsafe_code)]` everywhere else, Miri + fuzz mandatory. Expected gain: 5-15% over the safe version [estimate].

### 4.7 Filters
- **Important**: RAR filters are applied to the output, and the **window holds unfiltered data**. So the filter works on a copy -> the filter stage is naturally suited to a separate thread (while the decoder continues with the next block).
- E8/E8E9: a sliding scan; find 0xE8/0xE9 with SIMD (`_mm256_cmpeq_epi8` + `movemask`) and touch only the ones found. Scalar ~1-2 GB/s -> SIMD 8-15 GB/s [estimate]. The `e8e9_decode` in rars is a scalar loop.
- DELTA (sum of the previous value per channel): with channel count 1 there is a serial dependency; SIMD prefix-sum (shuffle-based) 3-6 GB/s [estimate]; naturally parallel with channels >= 2.
- ARM: offsets on BL instructions; simple, vectorizable.
- Measurement: in the normal archive 40.5 MB of filter = 0.03 s; that is, even for rars it is 2%. In a really executable-heavy archive (e.g. a 2 GB game directory) its share grows but stays below decoding.

### 4.8 Hash and encryption
- CRC32: `crc32fast` (PCLMULQDQ) is already >20 GB/s; done on the write thread. Measurement: 0.01 s for 400 MB.
- BLAKE2sp: optional in RAR5 (`-ht`); CRC32 by default. Implementation: the `blake2s_simd` (MIT) crate has `blake2sp` (8-way, AVX2) ~2-4 GB/s [estimate]; the 8 leaves are independent -> can also be parallel with one thread per leaf. Runs in the pipeline alongside the decoder, off the critical path.
- AES-NI + PBKDF2 cost is in section 1.3. In an encrypted **solid** archive, AES-CBC decryption (can be done in parallel) is not on the critical path: decoding is slower than AES.

### 4.9 Parallelism: even in a solid archive (main proposal)
Observation: RAR5 symbol parsing (Huffman decoding, length/distance computation) is **independent of the output data** (verified by ablation in this session: when the match copy was replaced with zero-filling, the decoding flow continued). Dependency: across blocks only `reps[4]`, `last_length` and the inherited tables (the tables are in the block's own header or "those of the previous block"). Therefore:

- **Stage A (command parsing)**: walk the block headers (headers are a few bytes, blocks are byte-sized -> block boundaries are cheap to find) and distribute blocks to worker threads. Each worker turns a block into a `Command` array: `Literal(run)`, `Match{len, dist}`, `Rep{slot, len}` (rep slot symbolic), `Filter{...}`.
- **Rep fix-up**: resolve the rep references at the start of a block (rare, only the first few commands) to real distances in a sequential pass; the rep LRU update is cheap. Alternative: instead of making A two-pass, a "pre-scan" short enough that, when a worker finishes a block, it computes the starting `reps` state of the next block.
- **Stage B (LZ application)**: a single thread applies the command arrays to the window in order (literal copy + match copy). Memory-bound; its share in the measured work is small (<10-20%) -> the real bottleneck is stage A; once A is parallelized, B remains.
- Stage C: filter/hash/write threads.
- Expected: A work ~1.2-1.4 s on a single thread (rars) / ~0.4-0.5 s (lean target); with 4 workers ~0.1-0.15 s; B ~0.15-0.25 s; total ~0.25-0.35 s <- ~3x below UnRAR's 0.94 s [estimate; B's command array memory traffic and thread synchronization need verification].
- **Risks/to verify**: (1) WinRAR's block size: large blocks (e.g. a few MB packed) do not break the parallelism granule, but with few blocks parallelism is limited; (2) when a block starts with "no tables" (inheritance), the A worker must know the previous block's table -> the chain of table blocks is sequential (tables are cheap: read in the header), decoding is parallel; (3) command array memory: 85 M commands x 8 B = 680 MB! -> **per-window/per-block streaming** (pipeline: while A finishes block k+W, B applies block k, with a bounded queue; ~16 blocks = 1 MB of commands), (4) filter records are carried in the command array together with their position. (5) Thread startup cost for short archives -> a threshold (e.g. packed < 4 MB single thread).
- This idea is **originally proposed in this report**; a similar structure exists in zstd multithreaded decoding and in the "parallel Huffman" literature (independent blocks), but here the distinction "parsing is independent, application is dependent" is used for RAR's solid case. It must be verified with a small prototype before use.

### 4.10 End-to-end pipeline (shared by solid / non-solid)
```
[read: mmap/ReadFile read-ahead + AES-CBC decryption]
   -> [decode (A: command parsing xN)  ->  B: LZ application]
   -> [filter + CRC/BLAKE2sp]  -> [writer: per file, multiple pending WriteFile]
```
- Bounded channels (1-4 MiB chunks), a buffer pool (no allocation), double buffering, a cancel flag per block (at ~100 µs intervals; 1000x less frequent than the per-symbol check in rars).
- Disk write [measured 1.2 GB/s sync included]: preallocate the file with its known size (`SetEndOfFile`/`FILE_ALLOCATION_INFO`), `FILE_FLAG_SEQUENTIAL_SCAN`, a single large write; with many small files **file creation** dominates (Windows Defender real-time scanning): spread file creation over a few threads.
- Non-solid: independent per file -> a thread pool (rars does this and is already faster than UnRAR: 0.60 vs 1.06 s).
- The 20-30% overhead outside the decoder (3.4) is targeted directly by this architecture: a zero-copy sink, an allocation pool.

### 4.11 Implementation comparison
| | rars 0.12.3 | libarchive rar5.c (not read; as known) | compcol rar5 | rar-codec |
|---|---|---|---|---|
| License | Apache-2.0 | BSD-2 | MIT | Apache-2.0 |
| Bit reader | bit position + 3 B slice | (C, 32/64-bit buffer assumed, not verified) | 16-bit peek | `acc = acc<<8 \| b` loop |
| Huffman | 10-bit fast + loop | table lookup | 9-bit primary | `DecodeTable` + long code |
| Window | VecDeque + pending | ring | ring (pow2) | ring (pow2) |
| Output path | double copy | - | pending + drain | `out` Vec |
| Parallelism | per file | none | none | none |
| Speed (solid) | 226 MB/s [measured] | not measured | not measured | 232 MB/s [measured] |
| Capability | full read+write, RAR1-5, encryption, recovery | RAR3/5 read | decoder only (RAR1-5; no container) | RAR3/5 read |

---

## 5. Can we beat UnRAR C++? An honest assessment

Baseline [measured]: UnRAR solid 427 MB/s, non-solid 377 MB/s end to end (CRC included, memory sink).

| Scenario | Target (single thread) | Target (multi-thread) | Confidence |
|---|---|---|---|
| Non-solid decoding | 450-600 MB/s/core [estimate] | 2-3 GB/s (disk/memory-bound) | High: rars parallel already beats UnRAR |
| Solid, **decoder core** | 500-800 MB/s [estimate] (5-7 ns/command) | 1.2-2 GB/s with the A/B split [estimate] | Medium: the A/B split is unverified |
| Solid, **end to end including disk write** | equal to UnRAR - 1.3x | 1.5-3x | Medium; disk/NTFS/Defender sets the ceiling |
| Encrypted (AES) | AES-NI + parallel decryption: decoding stays dominant, equal to UnRAR - 1.2x | | Medium |
| PPMd (RAR3) | **target equal to UnRAR**, beating it is hard | | Low-medium |
| RAR3 LZ+VM filter | similar to RAR5 LZ, with standard filters in native code -> equal - 1.3x | | Medium |

Honesty notes:
- UnRAR C++ is hand-tuned, ~11 ns per command measured end to end; it is not "easy" for a Rust decoder to exceed this on a single thread: it requires a libdeflate-class decoder and preprocessed tables. My estimate: on a single thread **close to equal - 1.3x**; a single thread is not enough for the "never slower" goal, the gain is settled by the **pipeline + the parallel A stage within solid**.
- The benchmark archives are rars level 1 output; on WinRAR archives (long matches, more reps, far distances -> cache misses) both sides run at a different speed; the **ratio** is uncertain. Be sure to re-measure with real archives (6.4).
- On single-core / slow-disk machines the difference stops depending on threads: "never slower" is guaranteed only if the single-thread core equals UnRAR -> **main gate: single-thread decoding <= UnRAR** (hypothetical worst case: 1 core).

---

## 6. Proposed architecture

### 6.1 Crate layout (workspace `rarchive/`)
| Crate | Content | Notes |
|---|---|---|
| `rarchive-core` | I/O-free decoders: bit reader, Huffman, RAR5 LZ, (later) RAR3 LZ/PPMd, filters, window, hash interfaces | `no_std + alloc` compatible; `#![forbid(unsafe_code)]` core; the `fastcopy` module is a separate feature (`unsafe-fast`) |
| `rarchive-format` | RAR4/RAR5 header parsers, vint, QO/locator, extra records | only `&[u8]`/`ReadAt` |
| `rarchive-crypto` | AES-CBC, PBKDF2-HMAC-SHA256, SHA-1 KDF, KDF cache | `aes`, `sha2`, `sha1`, `hmac`, `zeroize` |
| `rarchive-io` | Source types (file/mmap/memory), multi-volume joining, Windows file writer (preallocation, async), pipeline | |
| `rarchive` | Facade API (list, extract, progress/cancel) | |
| `rarchive-cli` | `rarchive l`, `x`, `t`, `bench` | |
| `fuzz/` | cargo-fuzz targets | |
| `rarchive-tests/` | corpus tests, differential tests | |

### 6.2 Streaming API shape (for a file manager)
```rust
let ar = Archive::open(source, OpenOptions { password_cb, max_window, limits })?;
for e in ar.entries() { /* name, size, packed, crc, directory?, solid?, encrypted?, method, mtime, attr, redirection */ }
ar.entries_quick()           // fast listing if QO is present; if used, extraction also reads from the same source (technote security note)

// single file (if solid, passes through earlier members with a sink-less "skip decode"; offers a cost estimate)
ar.extract(entry_id, &mut dyn Sink, &mut dyn Progress)?;

// all
ar.extract_all(&mut dyn SinkFactory, ExtractOptions { threads, ..})?;

trait SinkFactory { fn begin(&mut self, e:&Entry) -> Decision<Box<dyn FileSink>>; } // Skip / Write / Abort
trait FileSink: Send { fn write(&mut self, buf:&[u8])->io::Result<()>; fn finish(self:Box<Self>, v:Verified)->io::Result<()>; }
trait Progress { fn update(&mut self, p:&Info) -> Control; } // Continue | Cancel
```
- **The overwrite policy is always left to the caller** (`begin` returns Skip; the library itself never touches the file system; the CLI default is "rename").
- Skip decoding: in a solid archive, no hashing or writing is done for skipped members, only the window advances.
- Errors: a typed enum (`WrongPassword`, `CorruptHeader`, `ChecksumMismatch{entry}`, `LimitExceeded`, `Unsupported(feature)`), partial output is reported to the sink with `finish(Verified::Failed)`.

### 6.3 Security posture
- Fuzzing: `cargo-fuzz` (nightly, libFuzzer; works on Windows MSVC but ASan is limited -> prefer Linux CI or WSL). Targets: header parser, Huffman table builder, RAR5 decoder (random blocks + stateful), filter applier, RAR3 PPMd. Offline differential fuzzing: the UnRAR binary/`unrar` crate **only by running it** as an oracle (comparing output + error/success; without looking at its source).
- Limits (bomb protection): `max_window` (default 1 GiB, set by the caller), total unpacked size/ratio limit (e.g. 1000:1 + an optional absolute upper limit), header <= 2 MiB (technote), entry/record count, filter count and filter block <= 4 MiB, name length, nested directory depth, KDF iteration ceiling (like log2 <= 24; RAR says "a version-dependent threshold").
- Path safety (zip-slip): `..`, absolute paths, drive letters, `:` (ADS), reserved names (CON/NUL...), trailing dot/space, **reject symlink/junction redirection records by default**; escaping the extraction root directory is forbidden.
- `unsafe` auditing: a single module, Miri, fuzz, a separate CI job.

### 6.4 Test corpus strategy (without WinRAR installed)
1. **libarchive test files**: `libarchive/test/test_read_format_rar*.rar.uu`, `test_read_format_rar5_*.rar.uu` (uuencode; inside the BSD-2 repository). License: there is no separate exception for the repository's test data; redistribution under BSD-2 requires attribution; **check libarchive's COPYING and the file headers before using** [not verified]. They contain various (store, LZ, PPMd, filter, encrypted, multi-volume, ARM filter etc.) real WinRAR-produced archives; **the most valuable source**.
2. `rars` fixtures (`tests/rar50_fixtures.rs`, `rar15_40_fixtures.rs`; Apache-2.0) and the `bitplane/rar-research` spec/test repository (license to be checked).
3. Generators: the `rars` writer (can write RAR5 and RAR4; PPMd/VM if present). **Warning**: testing your own decoder with your own encoder hides errors; use the UnRAR oracle for differential testing.
4. Real, publicly available archives: Linux/BSD package repositories, Internet Archive, GitHub release files (**license/copyright check**; for testing only, and not in the repository but through a CI download script).
5. **Performance corpus**: at least 3 real WinRAR archives (solid + non-solid; executable-heavy, text-heavy, media-heavy); the user can produce them **themselves** with WinRAR on their machine (we do not need to install it); otherwise the trial. These are not put in the repository, the size is large.
6. Random/synthetic: archives produced with rars (fast regression), bit-level round-trip with `proptest`.
7. On every PR: a comparison of the output digests (CRC32/BLAKE2sp) of the whole corpus against `unrar` (oracle).

### 6.5 Phased plan and measurable exit criteria
| Phase | Content | Exit criterion |
|---|---|---|
| 0 | Fast-core spike: RAR5 LZ decoder (rars block parser + own bit reader/tables) and 3 real WinRAR archives | current harness solid: decoder function <= 0.9 s; <= 8 ns per command |
| 1 | RAR5 container + store | `l`/`x` on a store archive byte-for-byte equal to UnRAR output; store extraction >= UnRAR |
| 2 | RAR5 LZ (non-solid) | single thread: normal archive <= 1.0x UnRAR's time; parallel: <= 0.6 x UnRAR |
| 3 | Filters (DELTA, E8, E8E9, ARM) | filtered archive + oracle equality; E8 SIMD >= 5 GB/s |
| 4 | Solid + pipeline (+ A/B split spike) | solid end to end <= 0.9 x UnRAR (single-thread decoder) and <= 0.5 x (multi-thread) |
| 5 | Encryption (RAR5: AES-256+PBKDF2, header encryption, KDF cache) | correct/wrong password, <= 1.2 x UnRAR on an encrypted archive |
| 6 | Multi-volume | split + joined output equal, truncated volume error |
| 7 | RAR3/4 (LZ+VM standard+PPMd, AES-128) | the whole libarchive RAR3 corpus equal; LZ <= UnRAR, PPMd <= 1.1 x UnRAR |
| 8 | RAR7 (algorithm v1, large dictionary) | RAR7 archives (if any) equal; memory behavior bounded for 1-4 GB dictionaries |
| 9 | Recovery record verification/repair, quick-open | `l` speed (no header scan on a large archive) |
| 10 | Writer (store only → to be considered later, legal review) | see 7 |
| 11 | RAR2/1.5, fuzz hardening | 24 hours of fuzzing without a crash |

---

## 7. Clean-room / license notes

**Usable (with attribution):**
- `rars` (Apache-2.0): reading code is free; if we copy code, NOTICE/attribution (Apache §4: a copy of the license, notice of changes, NOTICE). Plan: do not copy code, read it to verify behavior. Constants/tables (slot formulas, layout) are factual.
- libarchive (BSD-2): attribution (copyright notice + license text), test files.
- `compcol` (MIT), `rar-codec` (Apache-2.0): the same.
- Ideas: libdeflate (Eric Biggers; MIT), zstd/huff0 (BSD/GPL dual), the Giesen blog, the Bloom blog, `zune-inflate` (MIT/Apache/Zlib), `miniz_oxide`.
- Rust crate dependencies: `crc32fast`, `aes`, `sha2`, `sha1`, `hmac`, `blake2s_simd` (all MIT/Apache).

**UnRAR license (RARLAB):** (general knowledge, source text not looked at) the UnRAR source may be used to develop software that extracts RAR archives, but **"may not be used to re-create the RAR compression algorithm"**. The `compcol` documentation (rar5/mod.rs) states this verbatim and notes that libarchive/The Unarchiver provide only a decoder. Implementing the format from the technote and writing the decoder clean-room is common practice (libarchive, 7-Zip, The Unarchiver). **For a writer (encoder)**: writing it with our own design without using the UnRAR source may fall outside the scope of the RARLAB license (rars does this), but this is a legal risk area; **v1 is decoder only**; a writer is considered only for the "store" method (uncompressed, a completely ordinary container); an LZ writer requires legal review. This is not legal advice.

**Provenance log:** for every constant/formula/bit layout, a record of "source: technote §x / rars file:line / libarchive function" will be kept (`docs/rarchive/provenance.md`). The provenance of rars's own source (the spec repository `bitplane/rar-research`) was not verified in this session; if that repository contains output derived from UnRAR, we do not use it. The provenance of the rar-codec repository (`danalec/rgx`) is unclear: since it has not been verified whether it is a port of UnRAR, it is recommended **not to use its contents as a source**, or not even to read it at header/structure level (in this session only file names, struct names and short greps were done; the algorithm was not read).

---

## 8. Open questions and risks
1. Block size, rep usage and far-distance ratio in WinRAR-produced archives: these determine the return of A/B parallelism.
2. Whether RAR7 algorithm version 1 has any difference other than the distance table (the use of `algorithm_version` in rars will be examined).
3. The ratio of per-file salts in encrypted archives (the benefit of the KDF cache).
4. Windows file creation cost (Defender) and the I/O strategy: to be measured (an archive heavy in small files: 50k files).
5. Provenance audit of `rar-codec` and the `rars` spec repository.
6. Verifying multi-core gains on low-core (2-4 core) machines.

## 9. Appendices
- Measurement tools (copies, outside the repository): `rars-prof` (a rars copy with counters), `rarprof` (measurement program), archives `bt/bench*.rar` (115 MB x2; can be deleted when no longer needed).
- Sources: https://www.rarlab.com/technote.htm ; `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rars-0.12.3/src/codec/rar50.rs` (lines 143-380, 963-1120, 1285-1512, 1969-2240), `.../src/crypto/rar50.rs`, `.../src/crc32/mod.rs` ; `.../compcol-0.7.8/src/rar5/mod.rs` ; https://github.com/bitplane/rars ; https://github.com/bitplane/rar-research ; libdeflate (Eric Biggers) decompress_template.h ; Fabian Giesen, "Reading bits in far too many ways" (fgiesen.wordpress.com 2018) ; Charles Bloom blog (cbloomrants.blogspot.com, Huffman/LZ decoding) ; zstd `huf_decompress.c`.

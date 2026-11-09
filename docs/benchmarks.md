# rarchive benchmarks

Machine: Ryzen 7 9800X3D (8 cores / 16 threads), NVMe, Windows 11. The archives are in the
operating system's file cache (warm). The output is decoded into memory and a CRC32 is taken; nothing
is written to disk (UnRAR was measured the same way). Tools: `rarspike` (`cmp`, `one`, `probe`, `burn`).

## Speed (2026-11-06, `cc3cf2b`, high priority, best of 3 runs)

| Archive | UnRAR (C++) | rarchive `extract` | rarchive `extract_parallel` |
|---|---|---|---|
| RustLegacyRemake2022.rar — WinRAR, 1.3 GB, 32 MB dictionary, 195 files | 2.79 s | 0.98 s (2.8×) | 0.28 s (**10.0×**) |
| The Forest — WinRAR, 1.2 GB, almost entirely stored | 0.70 s | 0.18 s (3.9×) | 0.17 s (4.1×) |
| bench-solid.rar — rars, 400 MB, solid | 0.95 s | 0.21 s (**4.5×**) | 0.21 s (4.6×) |
| bench.rar — rars, 400 MB, normal, 520 files | 1.03 s | 0.57 s (1.8×) | 0.063 s (**16.3×**) |

Correctness: the CRC32 of every file was compared with the one in the archive; in addition, the CC0
archives made with WinRAR (`crates/rarchive/tests/data/winrar`) are tested byte for byte, through both decoding paths.

## CPU and memory (single run)

UnRAR is also multithreaded: it uses ~2 cores on average. The total CPU time (how much work
was done) is lower in rarchive:

| | UnRAR | rarchive parallel |
|---|---|---|
| bench-solid, CPU-seconds | 2.36 | 0.91–1.06 |
| RustLegacy, CPU-seconds | 5.08 | 3.6–3.8 |

Peak memory (RustLegacy, parallel): 385–523 MB without a budget; 237–252 MB with a 256 MB budget
(the default). The measurement setup itself also holds memory (most of the 430 MB in the UnRAR row
comes from the test code, which reads the files fully into memory).

## Stutter (foreground probe)

`probe`: 8 normal-priority threads, each doing 2 ms of work + 4 ms of sleep (standing in for a
game's frame loop). "Delay": how much the 2 ms of work gets stretched, that is, the time the CPU was
given to something else. Measured for 8 s while the extraction was repeated back to back.

| Load | delayed frames (>4 ms) | worst |
|---|---|---|
| no load | 0.02–0.03% | 4–7 ms |
| UnRAR | 0.06–0.15% | 7–17 ms |
| rarchive parallel, normal priority | 2.1–2.8% | 67–115 ms |
| rarchive parallel, low priority (default) | 0.4–1.1% | 11–47 ms |

This table is **noisy**: during the measurement other programs were constantly using ~7–8 cores
(an IDE, another build, Robocopy), and in the next round 3.4% delay was seen even with no load.
The solid result: parallel extraction at normal priority makes the foreground visibly stutter,
which is why the default is low priority (`Priority::Low`: the lowest normal-class priority, wake-up
boost off). An exact comparison should be repeated when the machine is idle.

## Tried and dropped

- Huffman table of 9/11/12 bits: the difference from 10 bits is within noise.
- BMI2 copy (selected at run time): no difference on Zen 5; on Intel, where variable shifts are
  more expensive, it is expected to help, not measured.
- Prefetching the match source in the applier: slowed it down by 20–60%, removed.
- 8-byte commands: no speed difference, memory halved; kept.

## ZIP and 7z, extraction to disk (2026-11-06)

The same 381 MB / 520-file data, packed with NanaZip 7.0 at normal settings (ZIP: Deflate,
7z: LZMA2 single folder, 3 independent LZMA2 pieces). Extraction to disk, high priority, best of 3 runs;
CPU = total CPU time.

| | rustyfiles (rarchive) | NanaZip | Windows tar |
|---|---|---|---|
| ZIP | **0.39 s** (CPU 1.17 s, peak 49 MB) | 1.71 s | 0.85–0.99 s |
| 7z | 1.34 s (CPU 3.0 s, peak 350 MB) | **1.27 s** (2.3 s, 461 MB) | 3.5 s |

In 7z the limit is the single-core speed of the LZMA decoder (`lzma-rust2`, ~155 MB/s per piece); the three
pieces are decoded in parallel. The previous 7z path (`sevenz-rust2`) took 1.47 s and 621 MB. The memory
budget is now dynamic: 1/8 of free memory (256 MB–2 GB); at 256 MB this archive takes 1.8 s.

## RAR 1.5–4.x (RAR 4) read speed (2026-11-06)

Same method: decode into memory + CRC32, best of 7 runs, UnRAR and rarchive in turn (`rar4work/spike`,
`spike4`; UnRAR was run only as a reference, with the `unrar` crate). The archives were made with the `rars` writer
(the same format as the streams written by WinRAR 3.x/4.x; every archive produced was verified with UnRAR). The machine
was not completely free of other work: UnRAR's own time varies ±15% from run to run, so the range 0.95–1.10×
means "on par".

| Archive | UnRAR | rarchive `extract` | rarchive `extract_parallel` |
|---|---|---|---|
| bench4-lz — LZ, normal, 517 files, 290 MB (binary data with filters) | 1.23 s | 1.08 s (1.14×) | 0.134 s (**9.2×**) |
| bench4-solid — LZ, solid, 290 MB | 1.62 s | 1.04 s (**1.56×**) | 0.86 s (1.9×; a solid stream cannot be split) |
| bench4-ppmd — PPMd, normal, 2143 files, 42 MB (Rust source text) | 3.22 s | 3.16 s (1.02×) | 0.62 s (**5.2×**) |
| bench4-ppmd-solid — PPMd, solid, 42 MB | 2.68 s | 2.50 s (1.07×) | 2.38 s (1.13×; a solid stream cannot be split) |
| bench4-text-lz — LZ, solid, 42 MB text | 0.151 s | 0.066 s (**2.3×**) | 0.044 s (3.4×) |
| farmanager170.rar — WinRAR 3.x, solid PPMd, 3.3 MB (real archive) | 0.260 s | 0.207 s (1.25×) | — |
| bench4-v20 — RAR 2.0 (unpack 20), 31 MB text | 0.145 s | 0.060 s (**2.4×**) | 0.023 s (6.2×) |
| bench4-v15 — RAR 1.5 (unpack 15), 31 MB text | 0.206 s | 0.145 s (1.42×) | 0.045 s (4.6×) |

Where we lose / do not win: PPMd on a single stream is **on par** with UnRAR (1.02× and 1.07×; 0.97× was
also seen in separate runs). The PPMd model is sequential; a solid stream or a single large file does not
parallelize; the gain comes only from decoding many files concurrently in normal (independent per file)
archives. RAR 4 has no block-parallel parsing as in RAR 5 (the stream is sequential at the bit level, block
boundaries cannot be known).

Bottlenecks found during measurement: releasing and reallocating the PPMd model's 25 MB area after every file
(a 25% slowdown on a normal PPMd archive; now the model that is rarely used is kept, and released only after
groups of ≥4 MB decoded) and a bounds check on every access to the model memory (~30%: accesses now squeeze
the offset into its last 8 bytes, no panic path).

Correctness (separate from the speed comparison): the CRC32 of every member was compared with the one in the archive; in addition,
byte-for-byte tests with archives for which UnRAR produces the same bytes (`crates/rarchive/tests/rar4*.rs`): LZ, solid, PPMd (including
1–2 MB models whose model memory overflows and restarts: the allocator's merge/restart paths are
compatible with UnRAR), E8/E8E9/ITANIUM/DELTA/RGB/AUDIO filters, RAR 2.0 (including audio mode), RAR 1.5,
AES-128 (encrypted headers, passwords of ≥28 characters, multi-volume encrypted sets), multi-volume sets with old and new numbering.
Corrupt input: on 13,200 randomly corrupted archives (byte flips, truncation, random blocks)
zero panics, zero hangs (> 5 s).

## ZIP: read buffer on archives with very small members (2026-11-06 morning)

A ZIP of 20,000 small files (82 MB, made with Windows tar). `BufReader` threw away its buffer on every `seek`;
for each member (go to the local header, skip the header, read the data) a 1 MB buffer was filled twice
(~40 GB of memory copy). With `SeekBuf`, which keeps the buffer if the target is inside it:

| | before | after |
|---|---|---|
| `rarchive t` (decode into memory + CRC) | 4.9 s (CPU 1.8 s) | 0.04–0.13 s |
| extraction to disk (rustyfiles) | ~23 s | 16.6–18.4 s (Windows tar 21.6 s) |

The remaining time in extraction to disk is file creation/closing (antivirus scanning).

The same measurement with RAR5 (20,000 small files, a non-solid archive made with `rars`): `rarchive t` 0.05 s; extraction to disk
17.1–17.6 s (CPU 19–22 s: the file system and the antivirus filter driver working during file creation/closing are
charged to the process). Reducing the read buffer from 1 MB to 64 KB made no difference
(extra reading is negligible in parallel workers), reverted.

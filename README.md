# rarchive

A pure-Rust archive reader for RAR, ZIP and 7z, built to be fast and to stay out of the way.
Independent members, and independent blocks inside big RAR 5 and LZMA2 streams, decode in
parallel at low priority and within a memory budget, so a large extraction doesn't make the
rest of the machine stutter.

It is the archive engine of [rustyfiles](https://github.com/gelenmedya/rustyfiles), a file
manager for Windows. No C or C++ code is involved, and no UnRAR.

## Formats

| Format | What it reads |
|---|---|
| RAR 5 | Stored and compressed members, solid streams, DELTA / E8 / E8E9 / ARM filters, AES-256 with encrypted headers, volume sets, BLAKE2sp checksums |
| RAR 1.5 – 4.x | LZ, PPMd, the standard RarVM filters, RAR 2.0 audio, AES-128 encryption, volume sets |
| ZIP | Stored, Deflate, Deflate64, bzip2, LZMA, zstd, xz, PPMd; ZipCrypto and WinZip AES; ZIP64; split (`.zip.001`) and spanned (`.z01`) sets |
| 7z | LZMA, LZMA2, PPMd, the BCJ family, BCJ2, Delta, Deflate, Deflate64, BZip2, Zstd; AES-256, encrypted names included |

Not supported: RAR 1.3/1.4, the RAR 1.5/2.0 encryption, custom RarVM programs, RAR 7
dictionaries over 4 GB, and PKWARE strong encryption. `Archive::unsupported()` tells you which
member can't be extracted and why, before anything is decoded.

## Speed

Decoding into memory and checking every CRC32, best of three runs, on a Ryzen 7 9800X3D with
the archives in the OS file cache:

| Archive | UnRAR (C++) | rarchive, one thread | rarchive, parallel |
|---|--:|--:|--:|
| 1.3 GB WinRAR archive, 32 MB dictionary, 195 files | 2.79 s | 0.98 s | 0.28 s (10×) |
| 400 MB solid archive | 0.95 s | 0.21 s | 0.21 s (4.5×) |
| 400 MB archive, 520 files | 1.03 s | 0.57 s | 0.063 s (16×) |

UnRAR is multi-threaded too; rarchive also spends less CPU time in total on the same work.
Method, CPU and memory figures, and stutter measurements: [docs/olcumler.md](docs/olcumler.md)
(in Turkish).

## Use

```toml
[dependencies]
rarchive = { git = "https://github.com/gelenmedya/rarchive" }
```

Extraction goes through a `Sink`: you decide where each member's bytes go.

```rust
use rarchive::{Archive, Entry, Sink};

struct Collect(Vec<(String, Vec<u8>)>);

impl Sink for Collect {
    fn begin(&mut self, e: &Entry) -> std::io::Result<bool> {
        self.0.push((e.name.clone(), Vec::new()));
        Ok(!e.is_dir) // false skips the member (without decoding it, where the format allows)
    }
    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.last_mut().unwrap().1.extend_from_slice(bytes);
        Ok(())
    }
    fn end(&mut self, _: &Entry) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() -> rarchive::Result<()> {
    let archive = Archive::open_with_password("photos.rar", Some("secret"))?;
    for e in archive.entries() {
        println!("{} ({} bytes)", e.name, e.size);
    }
    archive.verify_password()?; // a wrong password fails here, before any output
    let mut out = Collect(Vec::new());
    archive.extract(&mut out)?;
    Ok(())
}
```

`Archive::extract_parallel(threads, make_sink)` runs the same on several threads, each with a
sink of its own. Any part of a volume set opens the whole set.

The `rarchive` binary is a small command line tool: `rarchive l`, `t` and `x` list, test and
extract an archive (`RARCHIVE_PASSWORD` holds the password).

## Tests

`cargo test` runs against archives in `tests/data` that were generated for this project and
checked against the official UnRAR and 7-Zip. Three third-party corpora (real WinRAR archives
and archives from historical RAR releases) are not redistributed here; the tests that use them
skip unless you put the files in place, as each folder's README explains.

Developed and tuned on Windows; the code has non-Windows fallbacks but is not tested there yet.

## License

MIT, see [LICENSE](LICENSE). The research notes in [docs](docs) (in Turkish) list the public
sources the decoders were written from.

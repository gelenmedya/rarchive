//! RAR 1.5-4.x: archives made with the `rars` writer (each one checked against the official
//! UnRAR when it was generated), WinRAR-made ones, volumes, encryption, damaged data.
use std::path::{Path, PathBuf};

fn data(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(p)
}

struct Collect(Vec<(String, Vec<u8>)>);
impl rarchive::Sink for Collect {
    fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
        if !e.is_dir {
            self.0.push((e.name.clone(), Vec::new()));
        }
        Ok(!e.is_dir)
    }
    fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.0.last_mut().unwrap().1.extend_from_slice(b);
        Ok(())
    }
    fn end(&mut self, _: &rarchive::Entry) -> std::io::Result<()> {
        Ok(())
    }
}

fn source(name: &str) -> Vec<u8> {
    std::fs::read(data("rar4/src").join(name)).unwrap_or_else(|e| panic!("source {name}: {e}"))
}

/// Extracts the archive (serially) and compares every file with its source.
fn check(name: &str, pw: Option<&str>, files: usize) {
    let a = rarchive::Archive::open_with_password(data(&format!("rar4/{name}")), pw).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(a.can_extract(), "{name}");
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(c.0.len(), files, "{name}");
    for (n, d) in c.0 {
        assert!(d == source(&n), "{name}: {n} differs");
    }
}

#[test]
fn lz_members() {
    check("lz.rar", None, 4);
    check("lz-solid.rar", None, 4);
    check("rar40.rar", None, 3);
}

#[test]
fn ppmd_members() {
    check("ppmd.rar", None, 2);
    check("ppmd-solid.rar", None, 3);
    check("ppmd-binary.rar", None, 2);
}

/// PPMd streams made with a test encoder over models of 1-2 MB that the data overflows (the
/// allocator glues free blocks and restarts the model several times). The generated archives
/// were checked against the official UnRAR, which decodes them to the same bytes: that is the
/// evidence that rarchive's model and allocator match the reference one.
#[test]
fn ppmd_models_that_overflow_and_restart() {
    for (order, mb, symbols, n) in [(8u32, 1usize, 64u32, 120_000usize), (16, 1, 16, 150_000), (64, 2, 8, 100_000)] {
        let mut x = order * 7 + mb as u32;
        let want: Vec<u8> = (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                ((x >> 16) % symbols) as u8
            })
            .collect();
        let name = format!("ppmd-o{order}-{mb}mb-s{symbols}");
        let a = rarchive::Archive::open(data(&format!("rar4/{name}.rar"))).unwrap();
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(c.0.len(), 1, "{name}");
        assert!(c.0[0].1 == want, "{name}");
    }
}

#[test]
fn vm_filters() {
    check("filters.rar", None, 5);
    check("filters-solid.rar", None, 5);
    for (n, files) in [("flt-e8", 1), ("flt-e8e9", 1), ("flt-itanium", 1), ("flt-rgb", 2), ("flt-rgb2", 1), ("flt-audio", 1), ("flt-audio4", 1), ("flt-delta", 1), ("flt-solid-e8", 3)] {
        check(&format!("{n}.rar"), None, files);
    }
}

#[test]
fn rar20_and_rar15() {
    check("v20.rar", None, 4);
    check("v20-solid.rar", None, 4);
    check("v15.rar", None, 4);
    check("v15-solid.rar", None, 3);
}

#[test]
fn entries_describe_members() {
    let a = rarchive::Archive::open(data("rar4/lz.rar")).unwrap();
    assert!(!a.is_solid() && !a.is_volume() && !a.needs_password());
    let e = a.entries().iter().find(|e| e.name == "kayıt.bin").expect("Unicode name decoded");
    assert!(!e.is_dir && e.size == source("kayıt.bin").len() as u64 && e.packed_size < e.size);
    assert_eq!(e.algo, 29);
    assert!(e.crc32.is_some() && !e.encrypted && !e.is_link);
    // the writer stored the number as the DOS time field
    assert_eq!(e.dos_time, Some(1_700_000_000));
    let d = a.entries().iter().find(|e| e.name == "klasör").expect("directory");
    assert!(d.is_dir);
    let s = rarchive::Archive::open(data("rar4/lz-solid.rar")).unwrap();
    assert!(s.is_solid() && !s.entries()[0].solid && s.entries()[1].solid && s.entries()[2].solid);
    assert_eq!(rarchive::Archive::open(data("rar4/v20.rar")).unwrap().entries()[1].algo, 20);
    assert_eq!(rarchive::Archive::open(data("rar4/v15.rar")).unwrap().entries()[1].algo, 15);
}

const PW: &str = "parola ✓ 123";

#[test]
fn encrypted_members() {
    check("enc.rar", Some(PW), 3);
    check("enc-ppmd-solid.rar", Some(PW), 2);
    // 28+ characters: key material over one SHA-1 block (the original tool's quirk)
    check("enc-long.rar", Some("bu parola yirmi sekiz karakterden uzundur ve 64 baytı aşar"), 2);
}

#[test]
fn encrypted_headers() {
    let p = data("rar4/enc-headers.rar");
    assert!(matches!(rarchive::Archive::open(&p), Err(rarchive::Error::NeedPassword)));
    assert!(matches!(rarchive::Archive::open_with_password(&p, Some("başlık şifresi!")), Err(rarchive::Error::BadPassword)));
    check("enc-headers.rar", Some("başlık şifresi"), 3);
}

#[test]
fn wrong_and_missing_passwords() {
    let a = rarchive::Archive::open(data("rar4/enc.rar")).unwrap();
    assert!(a.needs_password() && a.entries().iter().any(|e| e.encrypted));
    let mut c = Collect(Vec::new());
    assert!(matches!(a.extract(&mut c), Err(rarchive::Error::NeedPassword)));
    for pw in ["parola ✓ 124", "Parola ✓ 123", "x"] {
        let a = rarchive::Archive::open_with_password(data("rar4/enc.rar"), Some(pw)).unwrap();
        let mut c = Collect(Vec::new());
        assert!(matches!(a.extract(&mut c), Err(rarchive::Error::BadPassword)), "{pw}");
    }
    let a = rarchive::Archive::open_with_password(data("rar4/enc-ppmd-solid.rar"), Some("yanlış")).unwrap();
    assert!(matches!(a.extract(&mut Collect(Vec::new())), Err(rarchive::Error::BadPassword)));
}

/// No check value in RAR 3.x: `verify_password` decodes a small member, so a wrong password
/// is refused before anything is written and the right one passes.
#[test]
fn verify_password_decodes_to_tell() {
    for (name, right) in [("rar4/enc.rar", "parola ✓ 123"), ("rar4/enc-ppmd-solid.rar", "parola ✓ 123"), ("unrar-rs/crypted.rar", "unrar")] {
        if !data(name).exists() {
            continue; // third-party, not in the repository
        }
        let a = rarchive::Archive::open_with_password(data(name), Some("yanlış")).unwrap();
        assert!(matches!(a.verify_password(), Err(rarchive::Error::BadPassword)), "{name}");
        let a = rarchive::Archive::open_with_password(data(name), Some(right)).unwrap();
        a.verify_password().unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let a = rarchive::Archive::open(data("rar4/enc.rar")).unwrap();
    assert!(matches!(a.verify_password(), Err(rarchive::Error::NeedPassword)));
}

#[test]
fn volume_sets_open_from_any_volume() {
    for v in ["vol-new.part1.rar", "vol-new.part2.rar", "vol-new.part3.rar"] {
        let a = rarchive::Archive::open(data(&format!("rar4/{v}"))).unwrap();
        assert!(a.is_volume() && a.can_extract(), "{v}");
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(c.0.len(), 1, "{v}");
        assert!(c.0[0].1 == source("büyük.bin"), "{v}");
    }
    for v in ["vol-old.rar", "vol-old.r00"] {
        let a = rarchive::Archive::open(data(&format!("rar4/{v}"))).unwrap();
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert!(c.0.len() == 1 && c.0[0].1 == source("metin.txt"), "{v}");
    }
    // each volume's part of an encrypted member has its own salt
    for v in ["vol-enc.part1.rar", "vol-enc.part3.rar"] {
        let a = rarchive::Archive::open_with_password(data(&format!("rar4/{v}")), Some("parça şifresi")).unwrap();
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert!(c.0.len() == 1 && c.0[0].1 == source("büyük.bin"), "{v}");
    }
    let p = data("rar4/vol-enc-headers.r00");
    assert!(matches!(rarchive::Archive::open(&p), Err(rarchive::Error::NeedPassword)));
    let a = rarchive::Archive::open_with_password(&p, Some("parça şifresi")).unwrap();
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap();
    assert!(c.0.len() == 1 && c.0[0].1 == source("metin.txt"));
}

#[test]
fn a_missing_volume_lists_but_does_not_extract() {
    let tmp = std::env::temp_dir().join(format!("rarchive4-vol-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for v in ["vol-new.part1.rar", "vol-new.part3.rar"] {
        std::fs::copy(data(&format!("rar4/{v}")), tmp.join(v)).unwrap();
    }
    let a = rarchive::Archive::open(tmp.join("vol-new.part1.rar")).unwrap();
    assert!(a.entries().iter().any(|e| e.name == "büyük.bin"));
    assert!(!a.can_extract());
    let err = a.extract(&mut Collect(Vec::new())).unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parallel_extraction_agrees() {
    for (n, files, pw) in [("lz.rar", 4, None), ("lz-solid.rar", 4, None), ("ppmd.rar", 2, None), ("filters.rar", 5, None), ("v20.rar", 4, None), ("enc.rar", 3, Some(PW))] {
        let a = rarchive::Archive::open_with_password(data(&format!("rar4/{n}")), pw).unwrap();
        let out = std::sync::Mutex::new(Vec::<(String, Vec<u8>)>::new());
        struct S<'a>(&'a std::sync::Mutex<Vec<(String, Vec<u8>)>>, Vec<u8>, String);
        impl rarchive::Sink for S<'_> {
            fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
                self.1.clear();
                self.2 = e.name.clone();
                Ok(!e.is_dir)
            }
            fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.1.extend_from_slice(b);
                Ok(())
            }
            fn end(&mut self, e: &rarchive::Entry) -> std::io::Result<()> {
                if !e.is_dir {
                    self.0.lock().unwrap().push((self.2.clone(), std::mem::take(&mut self.1)));
                }
                Ok(())
            }
        }
        a.extract_parallel(4, || S(&out, Vec::new(), String::new())).unwrap_or_else(|e| panic!("{n}: {e}"));
        let got = out.into_inner().unwrap();
        assert_eq!(got.len(), files, "{n}");
        for (name, d) in got {
            assert!(d == source(&name), "{n}: {name}");
        }
    }
}

#[test]
fn winrar_made_rar4_archives() {
    if !data("unrar-rs/comment.rar").exists() {
        eprintln!("skipped: tests/data/unrar-rs is not in the repository (third-party test files, see its README)");
        return;
    }
    // crypted.rar: RAR 4, password "unrar"; its member is the same .gitignore the RAR 5 sample holds
    let want = {
        let a = rarchive::Archive::open(data("unrar-rs/comment.rar")).unwrap();
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap();
        c.0.remove(0).1
    };
    let a = rarchive::Archive::open_with_password(data("unrar-rs/crypted.rar"), Some("unrar")).unwrap();
    assert!(a.needs_password() && a.entries()[0].algo == 29);
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap();
    assert!(c.0.len() == 1 && c.0[0].1 == want);
    assert!(matches!(rarchive::Archive::open_with_password(data("unrar-rs/crypted.rar"), Some("Unrar")).unwrap().extract(&mut Collect(Vec::new())), Err(rarchive::Error::BadPassword)));
    let a = rarchive::Archive::open(data("unrar-rs/version.rar")).unwrap();
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap();
    assert_eq!(c.0[0].0, "VERSION");
    assert!(c.0[0].1.starts_with(b"unrar-") || !c.0[0].1.is_empty());
    // the first volume of a set whose other volumes are not here
    let a = rarchive::Archive::open(data("unrar-rs/archive.part1.rar")).unwrap();
    assert!(a.is_volume() && !a.can_extract() && a.entries().len() == 7);
    assert!(a.extract(&mut Collect(Vec::new())).is_err());
}

#[test]
fn rar_1_3_signature_is_not_supported() {
    let tmp = std::env::temp_dir().join(format!("rarchive4-old-{}.rar", std::process::id()));
    std::fs::write(&tmp, b"RE~^\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
    assert!(matches!(rarchive::Archive::open(&tmp), Err(rarchive::Error::OldFormat)));
    let _ = std::fs::remove_file(&tmp);
}

/// Damaged archives (flipped bytes, truncation) must produce errors or wrong-checksum
/// reports, never panics or hangs.
#[test]
fn damaged_archives_do_not_panic() {
    let tmp = std::env::temp_dir().join(format!("rarchive4-bad-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut tried = 0;
    for (name, pw) in [
        ("lz.rar", None),
        ("lz-solid.rar", None),
        ("ppmd.rar", None),
        ("ppmd-solid.rar", None),
        ("filters.rar", None),
        ("v20.rar", None),
        ("v20-solid.rar", None),
        ("v15.rar", None),
        ("enc.rar", Some(PW)),
        ("enc-headers.rar", Some("başlık şifresi")),
    ] {
        let orig = std::fs::read(data(&format!("rar4/{name}"))).unwrap();
        let mut x = 12345u32;
        let mut variants: Vec<Vec<u8>> = Vec::new();
        for k in 0..(if pw.is_some() { 4 } else { 12 }) {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            let mut v = orig.clone();
            // half of the flips land in the headers, half in the packed data
            let at = if k % 2 == 0 { (x >> 8) as usize % v.len() } else { (x >> 8) as usize % 100.min(v.len()) };
            v[at] ^= 1 << (x & 7);
            variants.push(v);
        }
        for cut in [10, 40, 100, orig.len() / 3, orig.len() / 2, orig.len() - 20].into_iter().take(if pw.is_some() { 3 } else { 6 }) {
            variants.push(orig[..cut.min(orig.len())].to_vec());
        }
        let t0 = std::time::Instant::now();
        for (i, v) in variants.iter().enumerate() {
            let p = tmp.join(format!("{name}-{i}.rar"));
            std::fs::write(&p, v).unwrap();
            tried += 1;
            let t1 = std::time::Instant::now();
            if let Ok(a) = rarchive::Archive::open_with_password(&p, pw) {
                let _ = a.extract(&mut Collect(Vec::new()));
                if i % 4 == 0 {
                    let _ = a.extract_parallel(2, || Collect(Vec::new()));
                }
            }
            if t1.elapsed().as_secs_f64() > 2.0 {
                eprintln!("slow: {name} variant {i}: {:?}", t1.elapsed());
            }
        }
        eprintln!("{name}: {:?}", t0.elapsed());
    }
    assert!(tried > 100);
    let _ = std::fs::remove_dir_all(&tmp);
}

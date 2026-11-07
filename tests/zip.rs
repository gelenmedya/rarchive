//! ZIP archives made by 7-Zip (NanaZip): every method and encryption we support, byte for byte.
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/zip")
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

fn check(name: &str, password: Option<&str>) {
    let a = rarchive::Archive::open_with_password(dir().join(name), password).unwrap();
    assert!(a.can_extract(), "{name}");
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(c.0.len(), 3, "{name}");
    for (n, d) in c.0 {
        assert_eq!(d, std::fs::read(dir().join("src").join(&n)).unwrap(), "{name}: {n}");
    }
}

#[test]
fn every_method() {
    for m in ["deflate", "deflate64", "bzip2", "lzma", "zstd", "xz", "ppmd"] {
        check(&format!("{m}.zip"), None);
    }
}

#[test]
fn encryption() {
    for (name, pw) in [("zipcrypto.zip", "sifre"), ("aes128.zip", "şifre"), ("aes256.zip", "şifre")] {
        let a = rarchive::Archive::open(dir().join(name)).unwrap();
        assert!(a.needs_password(), "{name}");
        assert!(matches!(a.verify_password(), Err(rarchive::Error::NeedPassword)), "{name}");
        let mut c = Collect(Vec::new());
        assert!(matches!(a.extract(&mut c), Err(rarchive::Error::NeedPassword)), "{name}");
        let a = rarchive::Archive::open_with_password(dir().join(name), Some("yanlis")).unwrap();
        assert!(matches!(a.verify_password(), Err(rarchive::Error::BadPassword)), "{name}");
        let a = rarchive::Archive::open_with_password(dir().join(name), Some(pw)).unwrap();
        a.verify_password().unwrap();
        check(name, Some(pw));
    }
}

#[test]
fn split_and_spanned_sets() {
    for (name, n) in [("split/bölünmüş.zip.001", 3), ("split/bölünmüş.zip.002", 3), ("spanned/yayılmış.zip", 3)] {
        let a = rarchive::Archive::open(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(a.can_extract(), "{name}");
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(c.0.len(), n, "{name}");
        for (f, d) in c.0 {
            assert_eq!(d, std::fs::read(dir().join("src").join(&f)).unwrap(), "{name}: {f}");
        }
    }
    // a spanned set with a disk missing: not readable as a whole
    let tmp = std::env::temp_dir().join(format!("rarchive-span-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for f in ["yayılmış.z01", "yayılmış.zip"] {
        std::fs::copy(dir().join("spanned").join(f), tmp.join(f)).unwrap();
    }
    let a = rarchive::Archive::open(tmp.join("yayılmış.zip"));
    assert!(a.is_err() || !a.unwrap().can_extract());
    let _ = std::fs::remove_dir_all(&tmp);
}

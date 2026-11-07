//! Multi-volume sets: opened from any volume, both naming styles, encryption, and a set
//! with a volume missing.
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/volumes")
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

fn check(volume: &str, password: Option<&str>) {
    let a = rarchive::Archive::open_with_password(dir().join(volume), password).unwrap_or_else(|e| panic!("{volume}: {e}"));
    assert!(a.is_volume() && a.can_extract(), "{volume}");
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap_or_else(|e| panic!("{volume}: {e}"));
    assert_eq!(c.0.len(), 3, "{volume}");
    for (n, d) in c.0 {
        assert_eq!(d, std::fs::read(dir().join("src").join(&n)).unwrap(), "{volume}: {n}");
    }
}

#[test]
fn sets_open_from_any_volume() {
    for v in ["vol.part1.rar", "vol.part2.rar", "vol.part3.rar", "vol-solid.rar", "vol-solid.r00", "vol-solid.r01"] {
        check(v, None);
    }
    check("vol-enc.part3.rar", Some("parça şifresi"));
    assert!(matches!(rarchive::Archive::open(dir().join("vol-enc.part1.rar")), Err(rarchive::Error::NeedPassword)));
}

#[test]
fn a_missing_volume_lists_but_does_not_extract() {
    let tmp = std::env::temp_dir().join(format!("rarchive-vol-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for v in ["vol.part1.rar", "vol.part3.rar"] {
        std::fs::copy(dir().join(v), tmp.join(v)).unwrap();
    }
    let a = rarchive::Archive::open(tmp.join("vol.part1.rar")).unwrap();
    assert!(a.entries().iter().any(|e| e.name == "gürültü.bin"));
    assert!(!a.can_extract());
    let mut c = Collect(Vec::new());
    let err = a.extract(&mut c).unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
    let _ = std::fs::remove_dir_all(&tmp);
}

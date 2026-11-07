//! Encrypted RAR 5: right, wrong and missing passwords, per-file and header encryption.
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

const PW: &str = "şifre 123";

#[test]
fn generated_archives_with_the_right_password() {
    for name in ["enc-files.rar", "enc-solid-headers.rar"] {
        let a = rarchive::Archive::open_with_password(data(&format!("generated/{name}")), Some(PW)).unwrap();
        assert!(a.needs_password() && a.can_extract(), "{name}");
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(c.0.len(), 3, "{name}");
        for (n, d) in c.0 {
            assert_eq!(d, std::fs::read(data(&format!("generated/src/{n}"))).unwrap(), "{name}: {n}");
        }
    }
}

#[test]
fn per_file_encryption_lists_without_a_password_but_needs_one_to_extract() {
    let a = rarchive::Archive::open(data("generated/enc-files.rar")).unwrap();
    assert!(a.entries().iter().any(|e| e.name == "klasör/b.bin" && e.encrypted));
    let mut c = Collect(Vec::new());
    assert!(matches!(a.extract(&mut c), Err(rarchive::Error::NeedPassword)));
}

#[test]
fn wrong_or_missing_passwords() {
    // encrypted names: no listing at all without the password
    assert!(matches!(rarchive::Archive::open(data("generated/enc-solid-headers.rar")), Err(rarchive::Error::NeedPassword)));
    assert!(matches!(
        rarchive::Archive::open_with_password(data("generated/enc-solid-headers.rar"), Some("şifre 124")),
        Err(rarchive::Error::BadPassword)
    ));
    let a = rarchive::Archive::open_with_password(data("generated/enc-files.rar"), Some("sifre 123")).unwrap();
    let mut c = Collect(Vec::new());
    assert!(matches!(a.extract(&mut c), Err(rarchive::Error::BadPassword)));
}

#[test]
fn winrar_encrypted_headers() {
    if !data("unrar-rs/comment-hpw-password.rar").exists() {
        eprintln!("skipped: tests/data/unrar-rs is not in the repository (third-party test files, see its README)");
        return;
    }
    let p = data("unrar-rs/comment-hpw-password.rar");
    assert!(matches!(rarchive::Archive::open(&p), Err(rarchive::Error::NeedPassword)));
    assert!(matches!(rarchive::Archive::open_with_password(&p, Some("Password")), Err(rarchive::Error::BadPassword)));
    let a = rarchive::Archive::open_with_password(&p, Some("password")).unwrap();
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap();
    assert_eq!(c.0.len(), 1);
    assert_eq!(c.0[0].0, ".gitignore");
}

#[test]
fn other_winrar_rar5_archives_extract_with_valid_checksums() {
    if !data("unrar-rs/comment.rar").exists() {
        eprintln!("skipped: tests/data/unrar-rs is not in the repository (third-party test files, see its README)");
        return;
    }
    for n in ["comment", "locked", "recovery-record", "solid", "unicode", "unicode-entry", "utf8"] {
        let a = rarchive::Archive::open(data(&format!("unrar-rs/{n}.rar"))).unwrap_or_else(|e| panic!("{n}: {e}"));
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(!c.0.is_empty(), "{n}");
    }

}

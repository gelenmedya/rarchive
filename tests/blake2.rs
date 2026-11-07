//! BLAKE2sp checksums: archives written by rars carry both CRC32 and BLAKE2sp (checked by
//! the official UnRAR when they were made); forcing BLAKE2sp makes every member go through
//! it, plain and MAC'ed (encrypted). Own test binary: the setting is read once.
use std::path::Path;

struct Count(usize);
impl rarchive::Sink for Count {
    fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
        if e.blake2sp.is_some() {
            self.0 += 1;
        }
        Ok(true)
    }
    fn data(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn end(&mut self, _: &rarchive::Entry) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn blake2sp_checksums_verify() {
    // SAFETY: set before any archive is opened, in a single-test binary
    unsafe { std::env::set_var("RARCHIVE_PREFER_BLAKE2", "1") };
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut checked = 0;
    for (p, pw) in [
        ("generated/enc-files.rar", Some("şifre 123")),
        ("generated/enc-solid-headers.rar", Some("şifre 123")),
        ("volumes/vol.part1.rar", None),
        ("volumes/vol-solid.rar", None),
    ] {
        let a = rarchive::Archive::open_with_password(data.join(p), pw).unwrap();
        let mut c = Count(0);
        a.extract(&mut c).unwrap_or_else(|e| panic!("{p}: {e}"));
        checked += c.0;
    }
    assert!(checked >= 10, "only {checked} members had BLAKE2sp");
}

//! The encrypted test archives through the block-parallel decoder (forced on with a zero
//! size threshold, in its own test binary so the setting can't race other tests).
use std::path::Path;

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

#[test]
fn encrypted_archives_block_parallel() {
    // SAFETY: set before any archive is opened, in a single-test binary
    unsafe { std::env::set_var("RARCHIVE_PIPE_MIN", "0") };
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/generated");
    for name in ["enc-files.rar", "enc-solid-headers.rar"] {
        let a = rarchive::Archive::open_with_password(dir.join(name), Some("şifre 123")).unwrap();
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(c.0.len(), 3);
        for (n, d) in c.0 {
            assert_eq!(d, std::fs::read(dir.join("src").join(&n)).unwrap(), "{name}: {n}");
        }
    }
}

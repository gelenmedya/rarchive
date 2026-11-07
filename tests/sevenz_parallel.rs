//! A 7z whose LZMA2 stream has several independent pieces, through the parallel piece
//! decoder and the read-ahead thread (forced on with a zero threshold; own test binary).
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
fn lzma2_pieces_in_parallel() {
    // SAFETY: set before any archive is opened, in a single-test binary
    unsafe { std::env::set_var("RARCHIVE_PIPE_MIN", "0") };
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/7z");
    for budget in [1u64, 64 << 20] {
        // a tiny budget forces pieces to wait their turn: must not deadlock
        let mut a = rarchive::Archive::open(dir.join("pieces.7z")).unwrap();
        a.set_memory_budget(budget);
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap();
        assert_eq!(c.0.len(), 6);
        for (n, d) in c.0 {
            assert_eq!(d, std::fs::read(dir.join("src").join(&n)).unwrap(), "{n}");
        }
    }
}

//! Damaged archives must give errors, never panics or hangs: every test archive, with bytes
//! flipped at many positions, is opened and extracted (with the right password where one
//! exists). Deterministic: a fixed pseudo-random sequence.
use std::path::{Path, PathBuf};

struct Sink;
impl rarchive::Sink for Sink {
    fn begin(&mut self, _: &rarchive::Entry) -> std::io::Result<bool> {
        Ok(true)
    }
    fn data(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn end(&mut self, _: &rarchive::Entry) -> std::io::Result<()> {
        Ok(())
    }
}

fn archives() -> Vec<(PathBuf, Option<&'static str>)> {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut out = Vec::new();
    for (sub, pw) in [("winrar", None), ("unrar-rs", Some("password")), ("generated", Some("şifre 123")), ("zip", Some("şifre")), ("7z", Some("şifre"))] {
        let Ok(rd) = std::fs::read_dir(d.join(sub)) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "rar" | "cbr" | "zip" | "7z") && std::fs::metadata(&p).unwrap().len() < 300_000 {
                out.push((p, pw));
            }
        }
    }
    out
}

#[test]
fn flipped_bytes_never_panic() {
    let tmp = std::env::temp_dir().join(format!("rarchive-damaged-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut x = 0x2545F491u32;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let mut runs = 0;
    for (p, pw) in archives() {
        let orig = std::fs::read(&p).unwrap();
        for k in 0..24 {
            let mut d = orig.clone();
            // a few flipped bytes: in headers (start, end) and in the data
            let at = match k % 3 {
                0 => (rnd() as usize) % d.len().min(200),
                1 => d.len() - 1 - (rnd() as usize) % d.len().min(200),
                _ => (rnd() as usize) % d.len(),
            };
            d[at] ^= (rnd() as u8) | 1;
            let f = tmp.join(p.file_name().unwrap());
            std::fs::write(&f, &d).unwrap();
            if let Ok(a) = rarchive::Archive::open_with_password(&f, pw) {
                let _ = a.extract(&mut Sink);
            }
            runs += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(runs > 500, "{runs}");
}

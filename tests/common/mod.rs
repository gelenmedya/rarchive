//! Shared by the WinRAR corpus tests.
use std::path::Path;

struct Collect(Vec<(String, Vec<u8>)>);
impl rarchive::Sink for Collect {
    fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
        self.0.push((e.name.clone(), Vec::new()));
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

pub fn dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/winrar"))
}

/// The corpus is third-party (CC0) and not in the repository: tests using it skip without it.
pub fn present() -> bool {
    let here = dir().join("testfile.rar5.rar").exists();
    if !here {
        eprintln!("skipped: tests/data/winrar is not in the repository (third-party test files, see its README)");
    }
    here
}

pub fn check_all() {
    if !present() {
        return;
    }
    let names = [
        "testfile.rar5.rar",
        "testfile.rar5.locked.rar",
        "testfile.rar5.rr.rar",
        "testfile.rar5.solid.rar",
        "testfile.rar5.cbr",
        "testfile.rar5.locked.cbr",
        "testfile.rar5.rr.cbr",
        "testfile.rar5.solid.cbr",
    ];
    for n in names {
        let a = rarchive::Archive::open(dir().join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
        // WinRAR stores modification times (in the extended time record): they must parse
        // to something plausible, 2000-2030
        for e in a.entries() {
            let t = e.mtime.unwrap_or_else(|| panic!("{n}: {} has no time", e.name));
            let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            assert!((946_684_800..1_893_456_000).contains(&secs), "{n}: {} time {secs}", e.name);
        }
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(!c.0.is_empty(), "{n}: no members");
        for (name, data) in c.0 {
            let want = std::fs::read(dir().join(&name)).unwrap();
            assert_eq!(data, want, "{n}: {name}");
        }
    }
}

/// The RAR 3 archives of the same corpus (they store DOS times only).
#[allow(dead_code)]
pub fn check_rar3() {
    if !present() {
        return;
    }
    let names = [
        "testfile.rar3.rar",
        "testfile.rar3.locked.rar",
        "testfile.rar3.av.rar",
        "testfile.rar3.rr.rar",
        "testfile.rar3.solid.rar",
        "testfile.rar3.cbr",
        "testfile.rar3.rr.cbr",
        "testfile.rar3.solid.cbr",
    ];
    for n in names {
        let a = rarchive::Archive::open(dir().join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
        for e in a.entries() {
            let t = e.dos_time.unwrap_or_else(|| panic!("{n}: {} has no DOS time", e.name));
            let year = (t >> 25) + 1980;
            assert!((2000..2030).contains(&year), "{n}: {} year {year}", e.name);
            assert_eq!(e.algo, 29, "{n}");
        }
        let mut c = Collect(Vec::new());
        a.extract(&mut c).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(!c.0.is_empty(), "{n}: no members");
        for (name, data) in c.0 {
            let want = std::fs::read(dir().join(&name)).unwrap();
            assert_eq!(data, want, "{n}: {name}");
        }
    }
}


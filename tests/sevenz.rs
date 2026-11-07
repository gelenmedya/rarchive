//! 7z archives made by 7-Zip (NanaZip): every coder setup and encryption we support.
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/7z")
}

struct Collect(Vec<(String, Option<Vec<u8>>)>);
impl rarchive::Sink for Collect {
    fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
        self.0.push((e.name.clone(), (!e.is_dir).then(Vec::new)));
        Ok(!e.is_dir)
    }
    fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.0.last_mut().unwrap().1.as_mut().unwrap().extend_from_slice(b);
        Ok(())
    }
    fn end(&mut self, _: &rarchive::Entry) -> std::io::Result<()> {
        Ok(())
    }
}

fn check(name: &str, password: Option<&str>) {
    let a = rarchive::Archive::open_with_password(dir().join(name), password).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(a.can_extract(), "{name}");
    for parallel in [false, true] {
        let mut c = Collect(Vec::new());
        if parallel {
            let all = std::sync::Mutex::new(Vec::new());
            struct P<'a>(&'a std::sync::Mutex<Vec<(String, Option<Vec<u8>>)>>, Collect);
            impl rarchive::Sink for P<'_> {
                fn begin(&mut self, e: &rarchive::Entry) -> std::io::Result<bool> {
                    self.1.begin(e)
                }
                fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
                    self.1.data(b)
                }
                fn end(&mut self, e: &rarchive::Entry) -> std::io::Result<()> {
                    self.1.end(e)?;
                    self.0.lock().unwrap().extend(self.1.0.drain(..));
                    Ok(())
                }
            }
            a.extract_parallel(4, || P(&all, Collect(Vec::new()))).unwrap_or_else(|e| panic!("{name}: {e}"));
            c.0 = all.into_inner().unwrap();
        } else {
            a.extract(&mut c).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let files: Vec<_> = c.0.iter().filter(|(_, d)| d.is_some()).collect();
        assert_eq!(files.len(), 6, "{name}: {:?}", c.0.iter().map(|x| &x.0).collect::<Vec<_>>());
        for (n, d) in files {
            assert_eq!(d.as_ref().unwrap(), &std::fs::read(dir().join("src").join(n)).unwrap(), "{name}: {n}");
        }
        assert!(c.0.iter().any(|(n, d)| n == "klasör/boş-klasör" && d.is_none()), "{name}: empty folder");
    }
}

#[test]
fn every_coder() {
    for n in ["lzma2", "lzma", "ppmd", "bcj", "bcj2", "delta", "deflate", "bzip2", "nonsolid"] {
        check(&format!("{n}.7z"), None);
    }
}

#[test]
fn encryption() {
    let a = rarchive::Archive::open(dir().join("aes.7z")).unwrap();
    assert!(a.needs_password());
    assert!(matches!(a.verify_password(), Err(rarchive::Error::NeedPassword)));
    let a = rarchive::Archive::open_with_password(dir().join("aes.7z"), Some("yanlış")).unwrap();
    assert!(matches!(a.verify_password(), Err(rarchive::Error::BadPassword)));
    check("aes.7z", Some("şifre"));
    assert!(matches!(rarchive::Archive::open(dir().join("aes-names.7z")), Err(rarchive::Error::NeedPassword)));
    assert!(matches!(rarchive::Archive::open_with_password(dir().join("aes-names.7z"), Some("yanlış")), Err(rarchive::Error::BadPassword)));
    check("aes-names.7z", Some("şifre"));
}

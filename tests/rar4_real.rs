//! Archives made by historical RAR releases (see tests/data/rar4/real/PROVENANCE.md): every
//! member passes its stored CRC32, and where the original payload is known it is compared
//! byte for byte. A separate binary so the decoder-feature counters are not raced.
use std::path::{Path, PathBuf};

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

fn real(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/rar4/real").join(p)
}

fn extract_all(p: &Path, pw: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let a = rarchive::Archive::open_with_password(p, pw).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    assert!(a.can_extract(), "{}", p.display());
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    c.0
}

#[test]
fn historical_rar_archives() {
    if !real("AUDIO.RAR").exists() {
        eprintln!("skipped: tests/data/rar4/real is not in the repository (third-party test files, see PROVENANCE.md)");
        return;
    }
    let known = [
        ("repeated_phrase_64k.txt", "ppmd_lz_match.txt"),
        ("lorem_127k.txt", "lorem_127k.txt"),
        ("lead.txt", "solid_e8_filter_lead.txt"),
        ("tiny_e8e9.exe", "solid_e8_filter_payload.exe"),
        ("README.md", "readme_154.md"),
        ("bigtext_64k.bin", "bigtext_64k.bin"),
    ];
    let before = rarchive::debug_counters();
    let mut compared = 0;
    for (n, pw) in [
        ("rarvm_audio_stereo_rar300.rar", None),
        ("rarvm_delta_4ch_rar300.rar", None),
        ("rarvm_itanium_synthetic_rar300.rar", None),
        ("rarvm_rgb_gradient_rar300.rar", None),
        ("rarvm_x86_e8_rar300.rar", None),
        ("rarvm_x86_e8e9_rar300.rar", None),
        ("ppmd_lz_match_rar300.rar", None),
        ("ppmd_lz_repeat_rar3.cbr", None),
        ("ppmd_lorem_rar300.rar", None),
        ("ppmd_solid_rar300.rar", None),
        ("ppmd_embedded_vm_filter.rar", None),
        ("solid_e8_filter_member_offset.rar", None),
        ("delta_64_channels.rar", None),
        ("ext_time_rar420.rar", None),
        ("readme_154_normal.rar", None),
        ("AUDIO.RAR", None),
        ("SOLID.RAR", None),
        ("unpack20_keep_tables.rar", None),
        ("multivol_oldnaming_rar300.r00", None),
        ("multivol_newnaming_rar300.part02.rar", None),
        ("per_file_rar300_password.rar", Some("password")),
        ("header_rar300_password.rar", Some("password")),
        ("header_rar420_password.rar", Some("password")),
        ("rar4_junrar_password.rar", Some("junrar")),
        ("rar4_junrar_header_encrypted.rar", Some("junrar")),
        ("rar4_junrar_file_content_encrypted_unicode.rar", Some("test")),
        ("rar4_mixed_visible_names_password.rar", Some("known-pass")),
    ] {
        for (name, d) in extract_all(&real(n), pw) {
            if let Some((_, f)) = known.iter().find(|(k, _)| *k == name) {
                assert!(d == std::fs::read(real(&format!("src/{f}"))).unwrap(), "{n}: {name}");
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 7);
    // what the historical archives exercise: the E8 and DELTA filters, PPMd blocks, LZ blocks
    let after = rarchive::debug_counters();
    let used: Vec<u64> = (0..10).map(|i| after[i] - before[i]).collect();
    assert!(used[0] > 0 && used[3] > 0 && used[6] > 0 && used[7] > 0, "{used:?}");
    // the contents the encrypted samples are documented to hold
    let hello = extract_all(&real("per_file_rar300_password.rar"), Some("password"));
    assert_eq!((hello[0].0.as_str(), crc32fast::hash(&hello[0].1)), ("hello.txt", 0xa538_535e));
    let j = extract_all(&real("rar4_junrar_password.rar"), Some("junrar"));
    assert_eq!(j[0].1, b"file1\n");
    let u = extract_all(&real("rar4_junrar_file_content_encrypted_unicode.rar"), Some("test"));
    assert_eq!((u[0].0.as_str(), u[0].1.as_slice()), ("新建文本文档.txt", &b"aaaaaaaaaa"[..]));
}

#[test]
fn extended_time_gives_an_absolute_mtime() {
    if !real("AUDIO.RAR").exists() {
        eprintln!("skipped: tests/data/rar4/real is not in the repository (third-party test files, see PROVENANCE.md)");
        return;
    }
    let a = rarchive::Archive::open(real("ext_time_rar420.rar")).unwrap();
    let e = &a.entries()[0];
    // WinRAR 4.20 stored the modification time with an extended-time record
    let t = e.mtime.expect("mtime from the extended time record");
    let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!((1_546_300_800..1_900_000_000).contains(&secs), "{secs}");
    assert!(e.dos_time.is_none());
}

#[test]
fn historical_volume_sets_and_rar20_names() {
    if !real("AUDIO.RAR").exists() {
        eprintln!("skipped: tests/data/rar4/real is not in the repository (third-party test files, see PROVENANCE.md)");
        return;
    }
    let a = rarchive::Archive::open(real("multivol_newnaming_rar300.part01.rar")).unwrap();
    assert!(a.is_volume());
    let mut c = Collect(Vec::new());
    a.extract(&mut c).unwrap();
    assert!(c.0[0].1 == std::fs::read(real("src/bigtext_64k.bin")).unwrap());
    assert_eq!(rarchive::Archive::open(real("AUDIO.RAR")).unwrap().entries()[0].name, "PCM_LR.WAV");
}

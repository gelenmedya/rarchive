//! Which decoder features the RAR 4 test archives exercise (a separate binary, so the
//! counters are not raced by other tests).
use std::path::{Path, PathBuf};

fn data(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(p)
}

struct Null;
impl rarchive::Sink for Null {
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

fn run(name: &str) -> [u64; 10] {
    let before = rarchive::debug_counters();
    rarchive::Archive::open(data(name)).unwrap().extract(&mut Null).unwrap_or_else(|e| panic!("{name}: {e}"));
    let after = rarchive::debug_counters();
    std::array::from_fn(|i| after[i] - before[i])
}

// [E8, E8E9, ITANIUM, DELTA, RGB, AUDIO, PPMd blocks, LZ blocks, PPMd restarts, PPMd gluing]
const E8: usize = 0;
const E8E9: usize = 1;
const ITANIUM: usize = 2;
const DELTA: usize = 3;
const RGB: usize = 4;
const AUDIO: usize = 5;
const PPMD: usize = 6;
const LZ: usize = 7;
const RESTARTS: usize = 8;
const GLUES: usize = 9;

#[test]
fn the_test_archives_cover_the_decoder() {
    assert!(run("rar4/lz.rar")[LZ] >= 1);
    assert!(run("rar4/ppmd.rar")[PPMD] >= 2);
    assert!(run("rar4/ppmd-solid.rar")[PPMD] >= 2);
    assert!(run("rar4/flt-e8.rar")[E8] >= 1);
    assert!(run("rar4/flt-e8e9.rar")[E8E9] >= 1);
    assert!(run("rar4/flt-itanium.rar")[ITANIUM] >= 1);
    assert!(run("rar4/flt-delta.rar")[DELTA] >= 1);
    let rgb = run("rar4/flt-rgb.rar");
    assert!(rgb[RGB] >= 2, "{rgb:?}");
    assert!(run("rar4/flt-rgb2.rar")[RGB] >= 1);
    assert!(run("rar4/flt-audio.rar")[AUDIO] >= 1);
    assert!(run("rar4/flt-audio4.rar")[AUDIO] >= 1);
    // E8 filter blocks across the solid members
    assert!(run("rar4/flt-solid-e8.rar")[E8] >= 3);
    // the PPMd model of the big archive ran out of memory: one restart at the start of the
    // block, more when it overflowed; free blocks were glued on the way
    let big = run("rar4/ppmd-o8-1mb-s64.rar");
    assert!(big[PPMD] == 1 && big[RESTARTS] >= 2 && big[GLUES] >= 1, "{big:?}");
    let wide = run("rar4/ppmd-o16-1mb-s16.rar");
    assert!(wide[RESTARTS] >= 3 && wide[GLUES] >= 10, "{wide:?}");
}

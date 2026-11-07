//! The WinRAR archives again, through the block-parallel decoder (forced on with a zero
//! size threshold; a separate test binary so the setting can't race other tests).
mod common;

#[test]
fn rar5_archives_extract_exactly_block_parallel() {
    // SAFETY: set before any archive is opened, in a single-test binary
    unsafe { std::env::set_var("RARCHIVE_PIPE_MIN", "0") };
    common::check_all();
}

//! Archives made by WinRAR itself (CC0 corpus): every member must extract byte for byte.
mod common;

#[test]
fn rar5_archives_extract_exactly() {
    common::check_all();
}

#[test]
fn rar3_archives_extract_exactly() {
    common::check_rar3();
}

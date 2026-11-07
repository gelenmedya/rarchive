//! RAR 5 output filters. They run on a copy of the decoded bytes; the window keeps the
//! unfiltered data that later matches refer to.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Delta { channels: u32 },
    E8,
    E8E9,
    Arm,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Filter {
    /// Absolute stream position of the first byte.
    pub start: u64,
    pub len: u32,
    pub kind: Kind,
}

/// Largest block a filter may cover (the format's own limit).
pub(crate) const MAX_LEN: u32 = 0x40_0000;

/// Applies `kind` to `data` in place; `file_pos` is the offset of `data[0]` in its file.
/// DELTA needs a second buffer: `scratch` is reused between calls.
pub(crate) fn apply(kind: Kind, data: &mut Vec<u8>, file_pos: u64, scratch: &mut Vec<u8>) {
    match kind {
        Kind::Delta { channels } => {
            let ch = channels as usize;
            scratch.clear();
            scratch.resize(data.len(), 0);
            let mut src = 0usize;
            for c in 0..ch {
                let mut prev = 0u8;
                let mut d = c;
                while d < data.len() {
                    prev = prev.wrapping_sub(data[src]);
                    scratch[d] = prev;
                    src += 1;
                    d += ch;
                }
            }
            std::mem::swap(data, scratch);
        }
        Kind::E8 | Kind::E8E9 => x86(data, file_pos as u32, kind == Kind::E8E9),
        Kind::Arm => arm(data, file_pos as u32),
    }
}

const X86_FILE_SIZE: u32 = 0x100_0000;

fn x86(data: &mut [u8], file_pos: u32, e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let mask = if e9 { 0xfe } else { 0xff };
    let limit = data.len() - 4;
    let mut i = 0usize;
    while i < limit {
        if data[i] & mask != 0xe8 {
            i += 1;
            continue;
        }
        let at = i + 1;
        let offset = file_pos.wrapping_add(at as u32) % X86_FILE_SIZE;
        let addr = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        if addr & 0x8000_0000 != 0 {
            // negative absolute address: becomes relative if it lands inside the file
            if addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                data[at..at + 4].copy_from_slice(&addr.wrapping_add(X86_FILE_SIZE).to_le_bytes());
            }
        } else if addr.wrapping_sub(X86_FILE_SIZE) & 0x8000_0000 != 0 {
            data[at..at + 4].copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
        }
        i += 5;
    }
}

fn arm(data: &mut [u8], file_pos: u32) {
    let mut i = 0usize;
    while i + 3 < data.len() {
        if data[i + 3] == 0xeb {
            let v = u32::from(data[i]) | u32::from(data[i + 1]) << 8 | u32::from(data[i + 2]) << 16;
            let v = v.wrapping_sub(file_pos.wrapping_add(i as u32) / 4);
            data[i] = v as u8;
            data[i + 1] = (v >> 8) as u8;
            data[i + 2] = (v >> 16) as u8;
        }
        i += 4;
    }
}

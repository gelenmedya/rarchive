//! The standard RarVM filters of RAR 3.x / 4.x, recognised by the CRC and length of their
//! bytecode and run natively (no VM): E8, E8E9, ITANIUM, DELTA, RGB, AUDIO.
//!
//! Provenance: the fingerprints (length + CRC32 of the program) and the filters' arithmetic
//! follow the `rars` crate (`codec/rar29/standard_filters.rs`, `codec/filters.rs`) and
//! libarchive's RAR reader; the code here is written for rarchive.

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

/// Recognises a standard filter by its bytecode (whose first byte is the XOR of the rest).
pub(super) fn identify(code: &[u8]) -> Option<Kind> {
    if code.iter().fold(0u8, |a, &b| a ^ b) != 0 {
        return None;
    }
    match (code.len(), crc32fast::hash(code)) {
        (53, 0xad57_6887) => Some(Kind::E8),
        (57, 0x3cd7_e57e) => Some(Kind::E8E9),
        (120, 0x3769_893f) => Some(Kind::Itanium),
        (29, 0x0e06_077d) => Some(Kind::Delta),
        (149, 0x1c2c_5dc8) => Some(Kind::Rgb),
        (216, 0xbc85_e701) => Some(Kind::Audio),
        _ => None,
    }
}

/// Applies a filter to `data` (a block at `file_offset` in its file), with the program's
/// initial registers `r`. Returns the filtered block (same length).
pub(super) fn apply(kind: Kind, data: &mut Vec<u8>, file_offset: u32, r: &[u32; 7]) -> Result<()> {
    super::count(kind as usize);
    match kind {
        Kind::E8 => e8(data, file_offset, false),
        Kind::E8E9 => e8(data, file_offset, true),
        Kind::Itanium => itanium(data, file_offset),
        Kind::Delta => {
            let ch = r[0] as usize;
            if ch == 0 || ch > 1024 {
                return Err(Error::Corrupt("DELTA filter channels"));
            }
            *data = delta(data, ch);
        }
        Kind::Rgb => {
            if r[0] < 3 || r[1] > 2 {
                return Err(Error::Corrupt("RGB filter parameters"));
            }
            *data = rgb(data, r[0] as usize - 3, r[1] as usize);
        }
        Kind::Audio => {
            let ch = r[0] as usize;
            if ch == 0 || ch > 128 {
                return Err(Error::Corrupt("AUDIO filter channels"));
            }
            *data = audio(data, ch);
        }
    }
    Ok(())
}

fn e8(data: &mut [u8], file_offset: u32, e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let limit = data.len() - 4;
    let mut i = 0;
    while i < limit {
        let b = data[i];
        if b != 0xE8 && !(e9 && b == 0xE9) {
            i += 1;
            continue;
        }
        let cur = i + 1;
        let offset = file_offset.wrapping_add(cur as u32);
        let addr = u32::from_le_bytes([data[cur], data[cur + 1], data[cur + 2], data[cur + 3]]);
        let new = if addr < 0x0100_0000 {
            Some(addr.wrapping_sub(offset))
        } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
            Some(addr.wrapping_add(0x0100_0000))
        } else {
            None
        };
        if let Some(v) = new {
            data[cur..cur + 4].copy_from_slice(&v.to_le_bytes());
        }
        i += 5;
    }
}

fn itanium(data: &mut [u8], file_offset: u32) {
    if data.len() <= 21 {
        return;
    }
    let base = file_offset >> 4;
    let blocks = (data.len() - 21).div_ceil(16);
    for block in 0..blocks {
        let pos = block * 16;
        let off = base.wrapping_add(block as u32);
        let mut mask = (0x334b_0000u32 >> (data[pos] & 0x1e)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + (mask as usize * 5 - 8);
                if (data[p + 3] >> mask) & 15 == 5 {
                    let raw = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let v = (raw >> mask).wrapping_sub(off) & 0x000f_ffff;
                    let raw = (raw & !(0x000f_ffff << mask)) | (v << mask);
                    data[p..p + 4].copy_from_slice(&raw.to_le_bytes());
                }
                mask += 1;
            }
        }
    }
}

fn delta(data: &[u8], channels: usize) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut src = 0;
    for ch in 0..channels {
        let mut prev = 0u8;
        let mut d = ch;
        while d < out.len() {
            prev = prev.wrapping_sub(data[src]);
            out[d] = prev;
            src += 1;
            d += channels;
        }
    }
    out
}

fn rgb(data: &[u8], width: usize, pos_r: usize) -> Vec<u8> {
    let len = data.len();
    let mut out = vec![0u8; len];
    let mut src = 0;
    for ch in 0..3 {
        let mut prev = 0u8;
        let mut i = ch;
        while i < len {
            let pred = if i >= width + 3 {
                let (up, ul) = (out[i - width], out[i - width - 3]);
                let p = i32::from(prev) + i32::from(up) - i32::from(ul);
                let (pa, pb, pc) = ((p - i32::from(prev)).abs(), (p - i32::from(up)).abs(), (p - i32::from(ul)).abs());
                if pa <= pb && pa <= pc {
                    prev
                } else if pb <= pc {
                    up
                } else {
                    ul
                }
            } else {
                prev
            };
            prev = pred.wrapping_sub(data[src]);
            out[i] = prev;
            src += 1;
            i += 3;
        }
    }
    let mut i = pos_r;
    while i + 2 < len {
        let g = out[i + 1];
        out[i] = out[i].wrapping_add(g);
        out[i + 2] = out[i + 2].wrapping_add(g);
        i += 3;
    }
    out
}

fn audio(data: &[u8], channels: usize) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut src = 0;
    for ch in 0..channels {
        let (mut prev_byte, mut prev_delta) = (0u32, 0i32);
        let (mut d1, mut d2) = (0i32, 0i32);
        let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
        let mut dif = [0u32; 7];
        let mut count = 0usize;
        let mut i = ch;
        while i < data.len() {
            let d3 = d2;
            d2 = prev_delta - d1;
            d1 = prev_delta;
            let pred = ((8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xff;
            let enc = data[src];
            src += 1;
            let dec = (pred as u8).wrapping_sub(enc);
            out[i] = dec;
            prev_delta = dec.wrapping_sub(prev_byte as u8) as i8 as i32;
            prev_byte = u32::from(dec);
            let d = (enc as i8 as i32) << 3;
            dif[0] += d.unsigned_abs();
            dif[1] += (d - d1).unsigned_abs();
            dif[2] += (d + d1).unsigned_abs();
            dif[3] += (d - d2).unsigned_abs();
            dif[4] += (d + d2).unsigned_abs();
            dif[5] += (d - d3).unsigned_abs();
            dif[6] += (d + d3).unsigned_abs();
            if count & 0x1f == 0 {
                let mut min = dif[0];
                let mut mi = 0;
                dif[0] = 0;
                for (j, v) in dif.iter_mut().enumerate().skip(1) {
                    if *v < min {
                        min = *v;
                        mi = j;
                    }
                    *v = 0;
                }
                match mi {
                    1 if k1 >= -16 => k1 -= 1,
                    2 if k1 < 16 => k1 += 1,
                    3 if k2 >= -16 => k2 -= 1,
                    4 if k2 < 16 => k2 += 1,
                    5 if k3 >= -16 => k3 -= 1,
                    6 if k3 < 16 => k3 += 1,
                    _ => {}
                }
            }
            count += 1;
            i += channels;
        }
    }
    out
}

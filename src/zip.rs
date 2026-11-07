//! ZIP: central directory, and per-member decoding.
//!
//! Every member is independent, so the archive layer decodes them in parallel; this
//! module only reads the directory and decodes one member at a time.
//! Methods: stored, Deflate (zlib-rs), Deflate64, bzip2, LZMA, zstd, xz, PPMd; encryption:
//! ZipCrypto and WinZip AES (see `zipcrypt`); numbered split sets (`x.zip.001`) and spanned
//! sets (`x.z01` ... `x.zip`). Not yet: PKWARE strong encryption.

use std::io::{Read, SeekFrom};

use flate2::{Decompress, FlushDecompress, Status};

use crate::archive::{Entry, filetime, unix_time};
use crate::error::{Error, Result};
use crate::volume::ReadSeek;
use crate::zipcrypt;

const EOCD: u32 = 0x0605_4b50;
const EOCD64: u32 = 0x0606_4b50;
const EOCD64_LOCATOR: u32 = 0x0706_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;

pub(crate) const STORED: u16 = 0;
pub(crate) const DEFLATE: u16 = 8;
const DEFLATE64: u16 = 9;
const BZIP2: u16 = 12;
const LZMA: u16 = 14;
const ZSTD: u16 = 93;
const XZ: u16 = 95;
const PPMD: u16 = 98;
const AES: u16 = 99;

/// ZIP specifics of a member.
#[derive(Clone, Debug)]
pub(crate) struct Extra {
    pub flags: u16,
    /// WinZip AES: (strength 1-3, vendor version: 1 = AE-1 with CRC, 2 = AE-2 without).
    pub aes: Option<(u8, u16)>,
}

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64le(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

/// The directory of a ZIP file. `volume` is set when it belongs to a spanned set that wasn't
/// read as one (`disk` is then the number of this, the last, disk).
pub(crate) struct Directory {
    pub entries: Vec<Entry>,
    pub volume: bool,
    pub disk: u32,
}

/// Reads the central directory (the file need not start with a local header: data in front
/// of the archive, as in self-extractors, is allowed). `bases`: for a spanned set read as one
/// stream, where each disk starts in it (offsets in the directory are per disk).
pub(crate) fn read_directory(f: &mut dyn ReadSeek, bases: Option<&[u64]>) -> Result<Directory> {
    let len = f.seek(SeekFrom::End(0))?;
    // end record: 22 bytes plus a comment of up to 64 KB, at the very end
    let tail_len = len.min(22 + 0xFFFF + 20);
    let mut tail = vec![0u8; tail_len as usize];
    f.seek(SeekFrom::Start(len - tail_len))?;
    f.read_exact(&mut tail)?;
    let at = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| u32le(&tail, i) == EOCD && i + 22 + u16le(&tail, i + 20) as usize <= tail.len())
        .ok_or(Error::NotArchive)?;
    let e = &tail[at..];
    let disk = u16le(e, 4);
    let cd_disk = u16le(e, 6);
    let mut count = u16le(e, 10) as u64;
    let mut cd_size = u32le(e, 12) as u64;
    let mut cd_offset = u32le(e, 16) as u64;
    let eocd_pos = len - tail_len + at as u64;
    let base = |d: u32| -> Result<u64> {
        match bases {
            Some(b) => b.get(d as usize).copied().ok_or(Error::Corrupt("disk number")),
            None => Ok(0),
        }
    };
    let mut volume = bases.is_none() && (disk != 0 || cd_disk != 0);
    let mut cd_disk = cd_disk as u32;
    // ZIP64: a locator right before the end record points to the 64-bit end record
    if at >= 20 && u32le(&tail, at - 20) == EOCD64_LOCATOR {
        let l = &tail[at - 20..at];
        let z64 = base(u32le(l, 4))? + u64le(l, 8);
        volume |= bases.is_none() && u32le(l, 16) > 1;
        let mut r = [0u8; 56];
        f.seek(SeekFrom::Start(z64))?;
        f.read_exact(&mut r)?;
        if u32le(&r, 0) != EOCD64 {
            return Err(Error::Corrupt("ZIP64 end record"));
        }
        volume |= bases.is_none() && (u32le(&r, 16) != 0 || u32le(&r, 20) != 0);
        cd_disk = u32le(&r, 20);
        count = u64le(&r, 32);
        cd_size = u64le(&r, 40);
        cd_offset = u64le(&r, 48);
    }
    // Data in front of the archive shifts every offset; the directory ends where the end
    // record (or the ZIP64 records) begin.
    let cd_end = if at >= 20 && u32le(&tail, at - 20) == EOCD64_LOCATOR { eocd_pos - 20 - 56 } else { eocd_pos };
    let cd_offset = base(cd_disk)? + cd_offset;
    let shift = if bases.is_some() { 0 } else { cd_end.checked_sub(cd_offset + cd_size).unwrap_or(0) };
    if cd_size > len || count > cd_size / 46 + 1 {
        return Err(Error::Corrupt("central directory size"));
    }
    let mut cd = vec![0u8; cd_size as usize];
    f.seek(SeekFrom::Start(cd_offset + shift))?;
    f.read_exact(&mut cd)?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut i = 0usize;
    while i + 46 <= cd.len() && u32le(&cd, i) == CENTRAL {
        let h = &cd[i..];
        let made_by = u16le(h, 4);
        let flags = u16le(h, 8);
        let method = u16le(h, 10);
        let dos = (u16le(h, 14) as u32) << 16 | u16le(h, 12) as u32;
        let crc = u32le(h, 16);
        let mut packed = u32le(h, 20) as u64;
        let mut size = u32le(h, 24) as u64;
        let (nlen, xlen, clen) = (u16le(h, 28) as usize, u16le(h, 30) as usize, u16le(h, 32) as usize);
        let start_disk = u16le(h, 34);
        let external = u32le(h, 38);
        let mut offset = u32le(h, 42) as u64;
        let mut start_disk32 = start_disk as u32;
        let total = 46 + nlen + xlen + clen;
        if i + total > cd.len() {
            return Err(Error::Corrupt("central directory entry"));
        }
        let raw_name = h[46..46 + nlen].to_vec();
        let extra = &h[46 + nlen..46 + nlen + xlen];
        let mut mtime = None;
        let mut unicode_name = None;
        let mut aes = None;
        let mut method = method;
        let mut x = 0usize;
        while x + 4 <= extra.len() {
            let (id, n) = (u16le(extra, x), u16le(extra, x + 2) as usize);
            let d = &extra[x + 4..(x + 4 + n).min(extra.len())];
            match id {
                // ZIP64: the fields that overflowed, in this order
                0x0001 => {
                    let mut k = 0;
                    for v in [&mut size, &mut packed, &mut offset] {
                        if *v == 0xFFFF_FFFF && k + 8 <= d.len() {
                            *v = u64le(d, k);
                            k += 8;
                        }
                    }
                    if start_disk == 0xFFFF && k + 4 <= d.len() {
                        start_disk32 = u32le(d, k);
                    }
                }
                // NTFS times: reserved, then tag 1 = mtime, atime, ctime (FILETIME)
                0x000a if d.len() >= 32 && u16le(d, 4) == 1 && u16le(d, 6) >= 24 => {
                    mtime = Some(filetime(u64le(d, 8)));
                }
                // extended timestamp: flags, then the Unix mtime
                0x5455 if d.len() >= 5 && d[0] & 1 != 0 && mtime.is_none() => {
                    let t = u32le(d, 1) as i32;
                    if t >= 0 {
                        mtime = Some(unix_time(t as u64, 0));
                    }
                }
                // WinZip AES: vendor version, "AE", strength, the real method
                0x9901 if d.len() >= 7 && method == AES => {
                    aes = Some((d[4], u16le(d, 0)));
                    method = u16le(d, 5);
                }
                // Info-ZIP Unicode path: valid only if it matches the stored name's CRC
                0x7075 if d.len() > 5 && d[0] == 1 && u32le(d, 1) == crc32fast::hash(&raw_name) => {
                    unicode_name = std::str::from_utf8(&d[5..]).ok().map(str::to_string);
                }
                _ => {}
            }
            x += 4 + n;
        }
        let utf8 = flags & 0x800 != 0;
        let name = unicode_name.unwrap_or_else(|| match std::str::from_utf8(&raw_name) {
            Ok(s) => s.to_string(),
            Err(_) if utf8 => String::from_utf8_lossy(&raw_name).into_owned(),
            Err(_) => cp437(&raw_name),
        });
        let host = made_by >> 8;
        let unix_mode = external >> 16;
        let is_dir = name.ends_with('/') || name.ends_with('\\') || (host == 0 && external & 0x10 != 0) || (host == 3 && unix_mode & 0o170000 == 0o040000);
        let is_link = host == 3 && unix_mode & 0o170000 == 0o120000;
        volume |= bases.is_none() && start_disk32 != 0;
        let mut name = name.replace('\\', "/");
        if is_dir {
            while name.ends_with('/') {
                name.pop();
            }
        }
        entries.push(Entry {
            name,
            raw_name,
            is_dir,
            size: if is_dir { 0 } else { size },
            packed_size: packed,
            attributes: external as u64,
            mtime,
            dos_time: (dos != 0).then_some(dos),
            // AE-2 doesn't store the CRC (the authentication code covers the data)
            crc32: if aes.is_some_and(|(_, v)| v == 2) { None } else { Some(crc) },
            blake2sp: None,
            encrypted: flags & 1 != 0,
            is_link,
            method,
            algo: 0,
            solid: false,
            dict_size: 0,
            split_before: false,
            split_after: false,
            data_offset: base(start_disk32)? + offset + shift,
            crypt: None,
            parts: Vec::new(),
            zip: Some(Box::new(Extra { flags, aes })),
            folder: None,
        });
        i += total;
    }
    Ok(Directory { entries, volume, disk: disk as u32 })
}

/// Whether this module can decode `e`.
pub(crate) fn supported(e: &Entry) -> bool {
    let x = e.zip.as_deref();
    // PKWARE strong encryption (flag 0x40) and AES without its extra field: no
    let crypto_ok = !e.encrypted || x.is_some_and(|x| x.flags & 0x40 == 0 && (e.method != AES || x.aes.is_some()));
    e.is_dir || (crypto_ok && matches!(e.method, STORED | DEFLATE | DEFLATE64 | BZIP2 | LZMA | ZSTD | XZ | PPMD))
}

/// Per-worker decoding state, reused between members.
pub(crate) struct State {
    inflate: Decompress,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
}

impl State {
    pub(crate) fn new() -> State {
        State { inflate: Decompress::new(false), inbuf: vec![0; 256 << 10], outbuf: vec![0; 256 << 10] }
    }
}

/// Positions `f` at member `e`'s data (past the local header, whose name and extra field
/// have their own lengths).
fn seek_data(f: &mut dyn ReadSeek, e: &Entry) -> Result<()> {
    f.seek(SeekFrom::Start(e.data_offset))?;
    let mut lh = [0u8; 30];
    f.read_exact(&mut lh)?;
    if u32le(&lh, 0) != LOCAL {
        return Err(Error::Corrupt("local header"));
    }
    f.seek(SeekFrom::Current(u16le(&lh, 26) as i64 + u16le(&lh, 28) as i64))?;
    Ok(())
}

/// The byte ZipCrypto's header must decrypt to: the CRC's top byte, or with a data
/// descriptor (flag 8) the DOS time's high byte.
fn zipcrypto_check(e: &Entry) -> u8 {
    let flags = e.zip.as_deref().map_or(0, |x| x.flags);
    if flags & 8 != 0 { (e.dos_time.unwrap_or(0) >> 8) as u8 } else { (e.crc32.unwrap_or(0) >> 24) as u8 }
}

/// Checks `password` against member `e` without decoding it.
pub(crate) fn verify(f: &mut dyn ReadSeek, e: &Entry, password: Option<&[u8]>) -> Result<()> {
    let pw = password.ok_or(Error::NeedPassword)?;
    seek_data(f, e)?;
    let raw = f.take(e.packed_size);
    match e.zip.as_deref().and_then(|x| x.aes) {
        Some((strength, _)) => zipcrypt::AesReader::new(raw, pw, strength).map(|_| ()),
        None => zipcrypt::ZipCryptoReader::new(raw, pw, zipcrypto_check(e)).map(|_| ()),
    }
}

/// Decodes member `e` from `f`, handing the output to `out`.
pub(crate) fn decode(
    f: &mut dyn ReadSeek,
    e: &Entry,
    st: &mut State,
    password: Option<&[u8]>,
    out: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    seek_data(f, e)?;
    let mut raw = f.take(e.packed_size);
    if !e.encrypted {
        return unpack(&mut raw, e, st, out);
    }
    let pw = password.ok_or(Error::NeedPassword)?;
    match e.zip.as_deref().and_then(|x| x.aes) {
        Some((strength, _)) => {
            let head = zipcrypt::aes_salt_len(strength)? as u64 + 2;
            let data = e.packed_size.checked_sub(zipcrypt::aes_overhead(strength)?).ok_or(Error::Corrupt("AES member too short"))?;
            let code = {
                let mut r = zipcrypt::AesReader::new((&mut raw).take(head + data), pw, strength)?;
                unpack(&mut r, e, st, out)?;
                // the code covers all of the data, even bytes the decoder didn't need
                std::io::copy(&mut r, &mut std::io::sink())?;
                r.code()
            };
            let mut stored = [0u8; 10];
            raw.read_exact(&mut stored)?;
            if code != stored {
                return Err(Error::Corrupt("ZIP AES authentication failed"));
            }
            Ok(())
        }
        None => {
            let mut r = zipcrypt::ZipCryptoReader::new(&mut raw, pw, zipcrypto_check(e))?;
            unpack(&mut r, e, st, out).map_err(|x| match x {
                // the header check lets 1 wrong password in 256 through
                Error::Corrupt(_) => Error::BadPassword,
                x => x,
            })
        }
    }
}

/// Decompresses `e`'s (decrypted) data from `src`.
fn unpack(src: &mut dyn Read, e: &Entry, st: &mut State, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    match e.method {
        STORED => pump(&mut src.take(e.size), e, st, out),
        DEFLATE => inflate(src, e, st, out),
        DEFLATE64 => pump(&mut deflate64::Deflate64Decoder::new(src), e, st, out),
        BZIP2 => pump(&mut bzip2::read::BzDecoder::new(src), e, st, out),
        ZSTD => pump(&mut zstd::stream::read::Decoder::new(src).map_err(Error::Io)?, e, st, out),
        XZ => pump(&mut lzma_rust2::XzReader::new(src, false), e, st, out),
        LZMA => {
            // version (2), properties size (2), properties: lc/lp/pb byte + dictionary size
            let mut h = [0u8; 4];
            src.read_exact(&mut h)?;
            let n = u16le(&h, 2) as usize;
            if n != 5 {
                return Err(Error::Corrupt("LZMA properties"));
            }
            let mut p = [0u8; 5];
            src.read_exact(&mut p)?;
            let dict = u32le(&p, 1).max(4096);
            // flag 2: the stream ends with a marker (size known anyway)
            let mut r = crate::lzma::LzmaReader::new(src, p[0], dict, e.size).map_err(|_| Error::Corrupt("LZMA properties"))?;
            pump(&mut r, e, st, out)
        }
        PPMD => {
            // PPMd variant I rev. 1: order, memory (MB) and restore method in two bytes
            let mut h = [0u8; 2];
            src.read_exact(&mut h)?;
            let v = u16::from_le_bytes(h);
            let (order, mem) = ((v & 0xF) as u32 + 1, (((v >> 4) & 0xFF) as u32 + 1) << 20);
            let restore = match v >> 12 {
                0 => ppmd_rust::RestoreMethod::Restart,
                1 => ppmd_rust::RestoreMethod::CutOff,
                _ => return Err(Error::Corrupt("PPMd restore method")),
            };
            let r = ppmd_rust::Ppmd8Decoder::new(src, order, mem, restore).map_err(|_| Error::Corrupt("PPMd parameters"))?;
            pump(&mut r.take(e.size), e, st, out)
        }
        _ => Err(Error::Unsupported("ZIP compression method")),
    }
}

/// Copies a decoder's output to `out`, checking the size against the directory.
fn pump(r: &mut dyn Read, e: &Entry, st: &mut State, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut produced = 0u64;
    loop {
        let n = match r.read(&mut st.outbuf) {
            Ok(n) => n,
            Err(x) if x.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Corrupt("data ends early")),
            Err(x) if x.kind() == std::io::ErrorKind::InvalidData || x.kind() == std::io::ErrorKind::Other => {
                return Err(Error::Corrupt("bad compressed data"));
            }
            Err(x) => return Err(x.into()),
        };
        if n == 0 {
            break;
        }
        produced += n as u64;
        if produced > e.size {
            return Err(Error::Corrupt("member larger than recorded"));
        }
        out(&st.outbuf[..n])?;
    }
    if produced != e.size {
        return Err(Error::Corrupt("member size differs from the directory"));
    }
    Ok(())
}

/// Deflate with zlib-rs, fed in large chunks.
fn inflate(src: &mut dyn Read, e: &Entry, st: &mut State, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    st.inflate.reset(false);
    let (mut have, mut pos) = (0usize, 0usize);
    let mut produced = 0u64;
    loop {
        if pos == have {
            have = src.read(&mut st.inbuf)?;
            pos = 0;
        }
        let (in0, out0) = (st.inflate.total_in(), st.inflate.total_out());
        let status = st
            .inflate
            .decompress(&st.inbuf[pos..have], &mut st.outbuf, FlushDecompress::None)
            .map_err(|_| Error::Corrupt("bad Deflate data"))?;
        let used = (st.inflate.total_in() - in0) as usize;
        pos += used;
        let n = (st.inflate.total_out() - out0) as usize;
        if used == 0 && n == 0 && status != Status::StreamEnd && have > 0 {
            return Err(Error::Corrupt("bad Deflate data"));
        }
        produced += n as u64;
        if produced > e.size {
            return Err(Error::Corrupt("member larger than recorded"));
        }
        if n > 0 {
            out(&st.outbuf[..n])?;
        }
        match status {
            Status::StreamEnd => break,
            _ if n == 0 && have == 0 => return Err(Error::Corrupt("Deflate data ends early")),
            _ => {}
        }
    }
    if produced != e.size {
        return Err(Error::Corrupt("member size differs from the directory"));
    }
    Ok(())
}

/// IBM PC code page 437, the ZIP default for names without the UTF-8 flag.
fn cp437(b: &[u8]) -> String {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    let high: Vec<char> = HIGH.chars().collect();
    b.iter().map(|&c| if c < 0x80 { c as char } else { high[(c - 0x80) as usize] }).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn cp437_table_is_complete() {
        assert_eq!(super::cp437(&[0x80, 0xff, b'a']), "Ç\u{a0}a");
    }
}

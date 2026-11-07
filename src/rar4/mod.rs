//! RAR 1.5 - 4.x archives: the block container (marker, main / file / service / end headers,
//! encrypted headers, volumes), and extraction through the decoders in the sub-modules.
//!
//! Provenance: the container layout is from RARLAB's public technote and checked against the
//! `rars` crate's `rar15_40` reader (Apache-2.0) and libarchive's
//! `archive_read_support_format_rar.c` (BSD-2). Written for rarchive; no UnRAR source was read.

mod bitio;
mod crypt;
mod filters;
mod ppmd;
mod unpack15;
mod unpack20;
mod unpack29;
mod window;

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::archive::{Entry, Sink};
use crate::crypto;
use crate::error::{Error, Result};
use crate::volume::{self, Naming, Part};

use unpack15::Unpack15;
use unpack20::Unpack20;
use unpack29::Unpack29;
use window::Win;

pub(crate) const SIG: &[u8; 7] = b"Rar!\x1a\x07\x00";

/// Test hooks: how often each decoder feature ran (E8, E8E9, ITANIUM, DELTA, RGB, AUDIO
/// filters, PPMd blocks, LZ blocks, PPMd model restarts, PPMd free-block gluing passes).
static COUNTERS: [std::sync::atomic::AtomicU64; 10] = [const { std::sync::atomic::AtomicU64::new(0) }; 10];

fn count(i: usize) {
    COUNTERS[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[doc(hidden)]
pub fn debug_counters() -> [u64; 10] {
    std::array::from_fn(|i| COUNTERS[i].load(std::sync::atomic::Ordering::Relaxed))
}

const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const NEWSUB_HEAD: u8 = 0x7a;
const END_HEAD: u8 = 0x7b;
/// A header's own size is 16 bits, so no header exceeds 64 KB (encrypted: rounded up to 16).
const LONG_BLOCK: u16 = 0x8000;

/// What the entries of an opened archive share: the password, derived keys, and the salts
/// of encrypted data (each volume's part of a member has its own).
pub(crate) struct Shared {
    password: Option<Vec<u8>>,
    keys: Mutex<Vec<([u8; 8], Arc<crypt::Key>)>>,
    /// (volume, data offset, salt) of every encrypted member part.
    salts: Vec<(u32, u64, [u8; 8])>,
    /// (volume, data offset, PPMd model MB) of members whose stream starts with a PPMd model.
    ppmd: Vec<(u32, u64, u16)>,
}

impl Shared {
    fn key(&self, salt: &[u8; 8]) -> Result<Arc<crypt::Key>> {
        let pw = self.password.as_deref().ok_or(Error::NeedPassword)?;
        if let Some(k) = self.keys.lock().unwrap().iter().find(|(s, _)| s == salt).map(|(_, k)| k.clone()) {
            return Ok(k);
        }
        // derived without holding the lock: other threads keep going
        let k = Arc::new(crypt::derive(pw, salt));
        self.keys.lock().unwrap().push((*salt, k.clone()));
        Ok(k)
    }

    fn salt_of(&self, part: &Part, default: &[u8; 8]) -> [u8; 8] {
        self.salts.iter().find(|(v, o, _)| *v == part.vol && *o == part.offset).map_or(*default, |x| x.2)
    }

    /// Derives the keys of the distinct salts on `threads` threads.
    pub(crate) fn prepare_keys(&self, entries: &[Entry], threads: usize, priority: crate::cpu::Priority) -> Result<()> {
        if self.password.is_none() {
            return Ok(());
        }
        let mut todo: Vec<[u8; 8]> = Vec::new();
        for e in entries.iter().filter(|e| e.crypt.is_some()) {
            for p in &e.parts {
                let s = self.salt_of(p, &entry_salt(e));
                if !todo.contains(&s) {
                    todo.push(s);
                }
            }
        }
        if todo.len() < 2 {
            return Ok(());
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads.clamp(1, todo.len()) {
                s.spawn(|| {
                    crate::cpu::apply_priority(priority);
                    while let Some(salt) = todo.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
                        let _ = self.key(salt);
                    }
                });
            }
        });
        Ok(())
    }
}

fn entry_salt(e: &Entry) -> [u8; 8] {
    e.crypt.as_ref().map_or([0; 8], |c| c.salt[..8].try_into().unwrap())
}

/// An opened RAR 1.5-4 archive (possibly a volume set).
pub(crate) struct Opened {
    pub entries: Vec<Entry>,
    pub solid: bool,
    pub volume: bool,
    pub volumes: Vec<PathBuf>,
    pub path: PathBuf,
    pub shared: Shared,
}

struct Parser {
    shared: Shared,
    entries: Vec<Entry>,
    solid: bool,
    volume: bool,
    /// Headers of the current volume are encrypted.
    header_crypt: bool,
}

/// One header block as read: its bytes (from the CRC field on, without padding), the data size
/// that follows, and the file bytes the header itself took.
struct Block {
    head: Vec<u8>,
    data_size: u64,
    used: u64,
}

impl Block {
    fn kind(&self) -> u8 {
        self.head[2]
    }
    fn flags(&self) -> u16 {
        u16::from_le_bytes([self.head[3], self.head[4]])
    }
}

pub(crate) fn open(path: &Path, password: Option<&[u8]>) -> Result<Opened> {
    let mut p = Parser {
        shared: Shared { password: password.map(<[u8]>::to_vec), keys: Mutex::new(Vec::new()), salts: Vec::new(), ppmd: Vec::new() },
        entries: Vec::new(),
        solid: false,
        volume: false,
        header_crypt: false,
    };
    let mut volumes = vec![path.to_path_buf()];
    let mut first = path.to_path_buf();
    let mut f = open_file(path)?;
    let mut more = p.read_volume(&mut f, 0)?;
    if p.volume {
        if let Some((naming, dir, k)) = Naming::of(path) {
            if k != 0 {
                first = dir.join(naming.name(0));
                let mut f0 = open_file(&first).map_err(|_| Error::Corrupt("the first volume of the set is missing"))?;
                p.entries.clear();
                p.shared.salts.clear();
                p.shared.ppmd.clear();
                volumes = vec![first.clone()];
                more = p.read_volume(&mut f0, 0)?;
            }
            let mut k = 1;
            while more {
                let vp = dir.join(naming.name(k));
                // a missing volume leaves its members incomplete (listed, not extractable)
                let Ok(mut f) = open_file(&vp) else { break };
                volumes.push(vp);
                more = p.read_volume(&mut f, k as u32)?;
                k += 1;
            }
        }
    }
    chain_stored_members(&mut p.entries);
    Ok(Opened { entries: p.entries, solid: p.solid, volume: p.volume, volumes, path: first, shared: p.shared })
}

/// A stored member inside a solid stream carries no solid flag of its own in some archives,
/// yet the compressed members around it continue one decoder state: marking it keeps the
/// group (which decodes in order, on one thread) from being cut in two.
fn chain_stored_members(entries: &mut [Entry]) {
    let n = entries.len();
    for i in 0..n {
        let e = &entries[i];
        if e.is_dir || e.solid || e.method != 0 || !entries[..i].iter().any(|p| !p.is_dir && p.method != 0) {
            continue;
        }
        let next = entries[i + 1..].iter().find(|x| !x.is_dir && x.method != 0);
        if next.is_some_and(|x| x.solid) {
            entries[i].solid = true;
        }
    }
}

fn open_file(p: &Path) -> Result<BufReader<File>> {
    let mut f = BufReader::with_capacity(64 << 10, File::open(p)?);
    let mut sig = [0u8; 7];
    f.read_exact(&mut sig).map_err(|_| Error::Corrupt("volume is not a RAR file"))?;
    if &sig != SIG {
        return Err(Error::Corrupt("volume is not a RAR 1.5-4 file"));
    }
    Ok(f)
}

fn crc16(b: &[u8]) -> u16 {
    crc32fast::hash(b) as u16
}

impl Parser {
    /// Reads one header block; `None` at the end of the file.
    fn read_block(&mut self, f: &mut BufReader<File>) -> Result<Option<Block>> {
        let mut first = [0u8; 8];
        let (head, used) = if self.header_crypt {
            match f.read(&mut first[..1])? {
                0 => return Ok(None),
                _ => f.read_exact(&mut first[1..8])?,
            }
            let key = self.shared.key(&first)?;
            let mut dec = crypt::Decrypt::new(&key);
            let mut b = [0u8; 16];
            f.read_exact(&mut b)?;
            dec.apply(&mut b);
            let size = u16::from_le_bytes([b[5], b[6]]) as usize;
            if size < 7 || !(0x72..=0x7b).contains(&b[2]) {
                return Err(Error::BadPassword);
            }
            let padded = size.div_ceil(16) * 16;
            let mut all = b.to_vec();
            all.resize(padded, 0);
            f.read_exact(&mut all[16..])?;
            dec.apply(&mut all[16..]);
            all.truncate(size);
            if crc16(&all[2..]) != u16::from_le_bytes([all[0], all[1]]) {
                return Err(Error::BadPassword);
            }
            (all, 8 + padded as u64)
        } else {
            let mut h = [0u8; 7];
            match f.read(&mut h[..1])? {
                0 => return Ok(None),
                _ => f.read_exact(&mut h[1..])?,
            }
            let size = u16::from_le_bytes([h[5], h[6]]) as usize;
            if size < 7 {
                return Err(Error::Corrupt("header size"));
            }
            let mut all = h.to_vec();
            all.resize(size, 0);
            f.read_exact(&mut all[7..])?;
            if crc16(&all[2..]) != u16::from_le_bytes([all[0], all[1]]) && all[2] != END_HEAD {
                return Err(Error::Corrupt("header checksum"));
            }
            (all, size as u64)
        };
        let flags = u16::from_le_bytes([head[3], head[4]]);
        // the packed size sits right after the 7 base bytes of blocks with data
        let data_size = if flags & LONG_BLOCK != 0 || head[2] == FILE_HEAD || head[2] == NEWSUB_HEAD {
            u64::from(u32::from_le_bytes(head.get(7..11).ok_or(Error::Corrupt("header size"))?.try_into().unwrap()))
        } else {
            0
        };
        Ok(Some(Block { head, data_size, used }))
    }

    /// Reads one volume's headers (`f` just past the marker). Returns whether another volume
    /// follows.
    fn read_volume(&mut self, f: &mut BufReader<File>, vol: u32) -> Result<bool> {
        let mut pos = 7u64;
        self.header_crypt = false;
        loop {
            let Some(b) = self.read_block(f)? else {
                // no end header: a split last member says the set goes on
                return Ok(self.volume && self.entries.last().is_some_and(|e| e.split_after));
            };
            pos += b.used;
            let flags = b.flags();
            let mut data_size = b.data_size;
            match b.kind() {
                MAIN_HEAD => {
                    self.volume |= flags & 0x01 != 0;
                    self.solid |= flags & 0x08 != 0;
                    if flags & 0x80 != 0 {
                        if self.shared.password.is_none() {
                            return Err(Error::NeedPassword);
                        }
                        self.header_crypt = true;
                    }
                }
                FILE_HEAD => {
                    let (mut e, salt, data_size_real) = parse_file(&b)?;
                    data_size = data_size_real;
                    let part = Part { vol, offset: pos, size: data_size };
                    e.packed_size = data_size;
                    e.data_offset = pos;
                    e.split_after = flags & 0x02 != 0;
                    if let Some(s) = salt {
                        self.shared.salts.push((vol, pos, s));
                    } else if e.method != 0 && matches!(e.algo, 29 | 36) && flags & 0x01 == 0 && data_size >= 2 {
                        // an unencrypted stream that opens with a PPMd model says how big it is
                        if let Ok(b) = f.fill_buf() {
                            if b.len() >= 2 && b[0] & 0xa0 == 0xa0 {
                                self.shared.ppmd.push((vol, pos, u16::from(b[1]) + 1));
                            }
                        }
                    }
                    let continued = flags & 0x01 != 0;
                    match self.entries.last_mut().filter(|p| continued && p.split_after && p.name == e.name) {
                        Some(prev) => {
                            prev.parts.push(part);
                            prev.packed_size += data_size;
                            prev.split_after = e.split_after;
                            if !e.split_after {
                                // the last part carries the whole file's checksum
                                prev.crc32 = e.crc32;
                            }
                        }
                        None => {
                            e.split_before = continued;
                            e.parts = vec![part];
                            self.entries.push(e);
                        }
                    }
                }
                END_HEAD => {
                    return Ok(flags & 0x01 != 0);
                }
                _ => {}
            }
            if data_size > 0 {
                f.seek_relative(data_size as i64)?;
                pos += data_size;
            }
        }
    }
}

/// Parses a file header block into an entry, the salt of its data (when encrypted), and the
/// size of its packed data.
fn parse_file(b: &Block) -> Result<(Entry, Option<[u8; 8]>, u64)> {
    let h = &b.head;
    if h.len() < 32 {
        return Err(Error::Corrupt("file header size"));
    }
    let flags = b.flags();
    let u32at = |i: usize| u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
    let (pack_low, unp_low) = (u64::from(u32at(7)), u64::from(u32at(11)));
    let host_os = h[15];
    let crc = u32at(16);
    let ftime = u32at(20);
    let unp_ver = h[24];
    let method = h[25];
    let name_len = u16::from_le_bytes([h[26], h[27]]) as usize;
    let attr = u32at(28);
    let mut p = 32;
    let (mut pack, mut unp) = (pack_low, unp_low);
    if flags & 0x100 != 0 {
        let hp = u64::from(u32::from_le_bytes(h.get(p..p + 4).ok_or(Error::Corrupt("file header size"))?.try_into().unwrap()));
        let hu = u64::from(u32::from_le_bytes(h.get(p + 4..p + 8).ok_or(Error::Corrupt("file header size"))?.try_into().unwrap()));
        p += 8;
        pack |= hp << 32;
        unp |= hu << 32;
        if unp_low == 0xffff_ffff && hu == 0xffff_ffff {
            unp = u64::MAX;
        }
    }
    let name_raw = h.get(p..p + name_len).ok_or(Error::Corrupt("file name"))?;
    p += name_len;
    let salt: Option<[u8; 8]> = if flags & 0x400 != 0 {
        let s = h.get(p..p + 8).ok_or(Error::Corrupt("file header salt"))?;
        p += 8;
        Some(s.try_into().unwrap())
    } else {
        None
    };
    let ext = if flags & 0x1000 != 0 { h.get(p..).unwrap_or(&[]) } else { &[] };

    // RAR 1.5 marks directories by the DOS attribute; later versions by the window bits
    let is_dir = flags & 0xe0 == 0xe0 || (unp_ver < 20 && host_os <= 2 && attr & 0x10 != 0);
    let (name, raw_name) = decode_name(name_raw, flags & 0x200 != 0);
    let encrypted = flags & 0x04 != 0;
    let is_link = host_os == 3 && attr & 0xf000 == 0xa000;
    let dict = if is_dir { 0 } else { 0x10000u64 << ((flags >> 5) & 7) };
    let mut mtime = None;
    let mut dos_time = (ftime != 0).then_some(ftime);
    if let Some(t) = ext_mtime(ftime, ext) {
        mtime = Some(t);
        dos_time = None;
    }
    if unp == u64::MAX && !is_dir {
        return Err(Error::Unsupported("members of unknown size"));
    }
    let e = Entry {
        name,
        raw_name,
        is_dir,
        size: if is_dir { 0 } else { unp },
        packed_size: 0,
        attributes: u64::from(attr),
        mtime,
        dos_time,
        crc32: Some(crc),
        blake2sp: None,
        encrypted,
        is_link,
        method: u16::from(method.saturating_sub(0x30)),
        algo: unp_ver,
        solid: flags & 0x10 != 0,
        dict_size: dict,
        split_before: false,
        split_after: false,
        data_offset: 0,
        crypt: if encrypted {
            salt.map(|s| {
                let mut full = [0u8; 16];
                full[..8].copy_from_slice(&s);
                Box::new(crypto::Params { kdf_log: 0, salt: full, iv: [0; 16], check: None, mac_checksums: false })
            })
        } else {
            None
        },
        parts: Vec::new(),
        zip: None,
        folder: None,
    };
    Ok((e, if encrypted { salt } else { None }, pack))
}

/// The name as `(name, raw name)`: Unicode names (flag 0x200) are decoded from the packed
/// UTF-16 form; others stay as stored (an OEM code page), `name` showing each byte as a
/// character. Backslashes become `/`.
fn decode_name(raw: &[u8], unicode: bool) -> (String, Vec<u8>) {
    let fix = |v: Vec<u8>| -> Vec<u8> { v.into_iter().map(|b| if b == b'\\' { b'/' } else { b }).collect() };
    if unicode {
        if let Some(s) = decode_unicode_name(raw) {
            let s = s.replace('\\', "/");
            return (s.clone(), s.into_bytes());
        }
    }
    let end = if unicode { raw.iter().position(|&b| b == 0).unwrap_or(raw.len()) } else { raw.len() };
    let raw = fix(raw[..end].to_vec());
    let name = match std::str::from_utf8(&raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    };
    (name, raw)
}

/// RAR's compressed Unicode name: the OEM name, a zero, a high byte, then 2-bit commands.
fn decode_unicode_name(raw: &[u8]) -> Option<String> {
    let z = raw.iter().position(|&b| b == 0)?;
    if z + 1 >= raw.len() {
        return Some(String::from_utf8_lossy(&raw[..z]).into_owned());
    }
    let std = &raw[..z];
    let high = u16::from(raw[z + 1]);
    let enc = &raw[z + 2..];
    let (mut i, mut flags, mut bits) = (0usize, 0u8, 0u8);
    let mut units: Vec<u16> = Vec::new();
    while i < enc.len() {
        if bits == 0 {
            flags = enc[i];
            i += 1;
            bits = 8;
            if i >= enc.len() {
                break;
            }
        }
        let mode = flags >> 6;
        flags <<= 2;
        bits -= 2;
        match mode {
            0 => {
                units.push(u16::from(*enc.get(i)?));
                i += 1;
            }
            1 => {
                units.push(high << 8 | u16::from(*enc.get(i)?));
                i += 1;
            }
            2 => {
                units.push(u16::from(*enc.get(i)?) | u16::from(*enc.get(i + 1)?) << 8);
                i += 2;
            }
            _ => {
                let l = *enc.get(i)?;
                i += 1;
                let (n, corr, hi) = if l & 0x80 != 0 {
                    let c = *enc.get(i)?;
                    i += 1;
                    ((l & 0x7f) as usize + 2, c, high)
                } else {
                    (l as usize + 2, 0, 0)
                };
                for _ in 0..n {
                    let lo = *std.get(units.len())?;
                    units.push(hi << 8 | u16::from(lo.wrapping_add(corr)));
                }
            }
        }
    }
    String::from_utf16(&units).ok()
}

/// The modification time with the extended-time record's detail (an odd second, and up to
/// three bytes of 100 ns ticks): the DOS time is local, so the result goes through the
/// local time zone.
fn ext_mtime(ftime: u32, ext: &[u8]) -> Option<std::time::SystemTime> {
    if ext.len() < 2 || ftime == 0 {
        return None;
    }
    let rmode = (u16::from_le_bytes([ext[0], ext[1]]) >> 12) as u8;
    if rmode & 8 == 0 {
        return None;
    }
    let n = (rmode & 3) as usize;
    let mut ticks = 0u32;
    for &b in ext.get(2..2 + n)? {
        ticks = u32::from(b) << 16 | ticks >> 8;
    }
    let (y, mo, d) = ((ftime >> 25) as u16 + 1980, ((ftime >> 21) & 15) as u16, ((ftime >> 16) & 31) as u16);
    let (h, mi, s) = (((ftime >> 11) & 31) as u16, ((ftime >> 5) & 63) as u16, ((ftime & 31) * 2) as u16);
    let t = local_to_system(y, mo, d, h, mi, s)?;
    let extra = std::time::Duration::from_secs(u64::from(rmode & 4 != 0)) + std::time::Duration::from_nanos(u64::from(ticks) * 100);
    Some(t + extra)
}

#[cfg(windows)]
fn local_to_system(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> Option<std::time::SystemTime> {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct St {
        year: u16,
        month: u16,
        dow: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        ms: u16,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn TzSpecificLocalTimeToSystemTime(tz: *const u8, local: *const St, utc: *mut St) -> i32;
        fn SystemTimeToFileTime(st: *const St, ft: *mut [u32; 2]) -> i32;
    }
    let local = St { year: y, month: mo, day: d, hour: h, minute: mi, second: s, ..St::default() };
    let (mut utc, mut ft) = (St::default(), [0u32; 2]);
    // SAFETY: plain Win32 calls on local structures
    unsafe {
        if TzSpecificLocalTimeToSystemTime(std::ptr::null(), &local, &mut utc) == 0 || SystemTimeToFileTime(&utc, &mut ft) == 0 {
            return None;
        }
    }
    Some(crate::archive::filetime(u64::from(ft[1]) << 32 | u64::from(ft[0])))
}

#[cfg(not(windows))]
fn local_to_system(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> Option<std::time::SystemTime> {
    // no time zone database here: the fields are taken as UTC
    let (y, m, d) = (i64::from(y), i64::from(mo), i64::from(d));
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s);
    u64::try_from(secs).ok().map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s))
}

/// Unpack versions this build decodes.
pub(crate) fn supported(e: &Entry) -> bool {
    e.is_dir || e.method == 0 || matches!(e.algo, 15 | 20 | 26 | 29 | 36)
}

/// One worker's decoder state.
pub(crate) struct Decoder {
    win: Win,
    inbuf: Vec<u8>,
    u29: Unpack29,
    u20: Unpack20,
    u15: Unpack15,
}

impl Decoder {
    pub(crate) fn new() -> Decoder {
        Decoder { win: Win::new(), inbuf: Vec::new(), u29: Unpack29::new(), u20: Unpack20::new(), u15: Unpack15::new() }
    }

    /// Frees what a finished group no longer needs: a big PPMd model, once the group decoded
    /// enough data to have touched much of it (a model that was barely used stays allocated:
    /// its untouched pages cost nothing, and the next group starts without a new allocation).
    fn trim(&mut self, decoded: u64) {
        if decoded >= (4 << 20) && self.u29.ppmd_memory() > (16 << 20) {
            self.u29.release();
        }
    }
}

/// Memory a group of `entries` needs while decoding: the window and tables, and the PPMd model
/// when a member's stream opens with one (its size is in the stream; later blocks of a solid
/// stream may ask for more, which is not seen here).
pub(crate) fn group_memory(sh: &Shared, entries: &[Entry]) -> u64 {
    let size: u64 = entries.iter().filter(|e| !e.is_dir && e.method != 0).map(|e| e.size).sum();
    let win = (size.min(window::MAX_WINDOW as u64) as usize).next_power_of_two().max(64 << 10) as u64;
    let model = entries.iter().flat_map(|e| e.parts.first()).flat_map(|p| sh.ppmd.iter().filter(move |(v, o, _)| *v == p.vol && *o == p.offset)).map(|x| u64::from(x.2) << 20).max().unwrap_or(0);
    win + (512 << 10) + model
}

/// Decodes one group of dependent members.
pub(crate) fn extract_chain(
    sh: &Shared,
    entries: &[Entry],
    files: &mut volume::Files,
    dec: &mut Option<Box<Decoder>>,
    sink: &mut dyn Sink,
) -> Result<()> {
    let dec = dec.get_or_insert_with(|| Box::new(Decoder::new()));
    let r = chain(sh, entries, files, dec, sink);
    dec.trim(entries.iter().filter(|e| !e.is_dir && e.method != 0).map(|e| e.size).sum());
    r
}

fn chain(sh: &Shared, entries: &[Entry], files: &mut volume::Files, dec: &mut Decoder, sink: &mut dyn Sink) -> Result<()> {
    for e in entries.iter().filter(|e| !e.is_dir) {
        if e.encrypted && e.crypt.is_none() {
            return Err(Error::Unsupported("encryption method"));
        }
        if e.split_before || e.split_after {
            return Err(Error::Corrupt("a volume of the set is missing"));
        }
        if !supported(e) {
            return Err(Error::Unsupported("RAR unpack version"));
        }
    }
    // keys first: a wrong or missing password stops here, before anything is written
    let mut keys: Vec<Vec<Arc<crypt::Key>>> = Vec::with_capacity(entries.len());
    for e in entries {
        let mut ks = Vec::new();
        if !e.is_dir && e.crypt.is_some() {
            let d = entry_salt(e);
            for p in &e.parts {
                ks.push(sh.key(&sh.salt_of(p, &d))?);
            }
        }
        keys.push(ks);
    }
    let total: u64 = entries.iter().filter(|e| !e.is_dir && e.method != 0).map(|e| e.size).sum();
    if total > 0 {
        dec.win.reserve(total);
    }
    for (i, e) in entries.iter().enumerate() {
        let want = sink.begin(e)?;
        if e.is_dir {
            sink.end(e)?;
            continue;
        }
        let later = entries[i + 1..].iter().any(|n| !n.is_dir && n.solid);
        if !want && !later {
            continue;
        }
        let mut crc = crc32fast::Hasher::new();
        let mut out = |d: &[u8]| -> Result<()> {
            crc.update(d);
            if want {
                sink.data(d)?;
            }
            Ok(())
        };
        let res = if e.encrypted && keys[i].windows(2).all(|w| Arc::ptr_eq(&w[0], &w[1])) {
            // one salt: the cipher runs on across the volumes' parts as a single stream
            let mut src = crypt::DecryptReader::new(files.reader(&e.parts), &keys[i][0]);
            decode_member(dec, &mut src, e, later, &mut out)
        } else if e.encrypted {
            let mut src = EncSource::new(files, &e.parts, &keys[i]);
            decode_member(dec, &mut src, e, later, &mut out)
        } else {
            let mut src = files.reader(&e.parts);
            decode_member(dec, &mut src, e, later, &mut out)
        };
        if let Err(err) = res {
            return Err(if e.encrypted && matches!(err, Error::Corrupt(_) | Error::BadChecksum(_)) { Error::BadPassword } else { err });
        }
        if e.crc32.is_some_and(|c| c != crc.finalize()) {
            return Err(if e.encrypted { Error::BadPassword } else { Error::BadChecksum(e.name.clone()) });
        }
        if want {
            sink.end(e)?;
        }
    }
    Ok(())
}

fn decode_member(dec: &mut Decoder, src: &mut dyn Read, e: &Entry, more: bool, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    if e.method == 0 {
        return crate::unpack5::copy_stored(src, e.size, out);
    }
    if e.size == 0 && e.packed_size == 0 {
        return Ok(());
    }
    let Decoder { win, inbuf, u29, u20, u15 } = dec;
    match e.algo {
        29 | 36 => u29.decode_file(win, inbuf, src, e.size, e.solid, more, out),
        20 | 26 => u20.decode_file(win, inbuf, src, e.size, e.solid, out),
        15 => u15.decode_file(win, inbuf, src, e.size, e.solid, out),
        _ => Err(Error::Unsupported("RAR unpack version")),
    }
}

/// The packed data of an encrypted member: each volume's part decrypts with its own key.
struct EncSource<'a> {
    files: &'a mut volume::Files,
    parts: &'a [Part],
    keys: &'a [Arc<crypt::Key>],
    idx: usize,
    used: u64,
    dec: Option<crypt::Decrypt>,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
}

impl<'a> EncSource<'a> {
    fn new(files: &'a mut volume::Files, parts: &'a [Part], keys: &'a [Arc<crypt::Key>]) -> Self {
        EncSource { files, parts, keys, idx: 0, used: 0, dec: None, buf: vec![0; 64 << 10], pos: 0, len: 0 }
    }
}

impl Read for EncSource<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.len {
            let Some(p) = self.parts.get(self.idx) else { return Ok(0) };
            let left = p.size - self.used;
            if left < 16 {
                self.idx += 1;
                self.used = 0;
                self.dec = None;
                continue;
            }
            if self.dec.is_none() {
                self.dec = Some(crypt::Decrypt::new(&self.keys[self.idx]));
            }
            let n = (left.min(self.buf.len() as u64) as usize) & !15;
            let sub = [Part { vol: p.vol, offset: p.offset + self.used, size: n as u64 }];
            self.files.reader(&sub).read_exact(&mut self.buf[..n])?;
            self.dec.as_mut().unwrap().apply(&mut self.buf[..n]);
            self.used += n as u64;
            self.pos = 0;
            self.len = n;
        }
        let k = out.len().min(self.len - self.pos);
        out[..k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

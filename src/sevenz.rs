//! 7z: headers (plain or packed / encrypted), folders and their coder graphs, file list.
//!
//! References: Igor Pavlov's public-domain format description (7zFormat.txt); details such
//! as the AES property layout and key derivation were cross-checked against the
//! `sevenz-rust2` crate (Apache-2.0). Decoding uses `lzma-rust2` (LZMA, LZMA2, BCJ family,
//! BCJ2, Delta), `ppmd-rust` (PPMd H), and the crates the ZIP side already uses.
//!
//! A folder is a solid block: its members decode in order; separate folders decode in
//! parallel (the archive layer treats each folder as one group).

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::archive::{Entry, filetime};
use crate::error::{Error, Result};

pub(crate) const SIGNATURE: &[u8; 6] = b"7z\xBC\xAF\x27\x1C";

/// A coder in a folder: method id, stream counts, properties.
#[derive(Clone, Debug)]
pub(crate) struct Coder {
    id: Vec<u8>,
    ins: usize,
    outs: usize,
    props: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Folder {
    coders: Vec<Coder>,
    /// (in stream index, out stream index): coder outputs feeding coder inputs.
    binds: Vec<(usize, usize)>,
    /// In stream indices that read packed streams, in packed stream order.
    packed: Vec<usize>,
    /// Size of every coder output stream.
    sizes: Vec<u64>,
    pub crc: Option<u32>,
    /// Absolute offsets and sizes of this folder's packed streams.
    pub pack: Vec<(u64, u64)>,
}

impl Folder {
    /// The output stream nobody consumes: the folder's result.
    fn main_out(&self) -> Option<usize> {
        let total: usize = self.coders.iter().map(|c| c.outs).sum();
        (0..total).find(|o| !self.binds.iter().any(|&(_, b)| b == *o))
    }

    pub(crate) fn size(&self) -> u64 {
        self.main_out().and_then(|o| self.sizes.get(o).copied()).unwrap_or(0)
    }

    fn encrypted(&self) -> bool {
        self.coders.iter().any(|c| c.id == AES)
    }

    /// Rough memory a decoder for this folder needs (dictionaries, PPMd models).
    pub(crate) fn memory(&self) -> u64 {
        self.coders
            .iter()
            .map(|c| match c.id.as_slice() {
                LZMA if c.props.len() >= 5 => u32::from_le_bytes(c.props[1..5].try_into().unwrap()) as u64,
                LZMA2 if !c.props.is_empty() => lzma2_dict(c.props[0]) as u64,
                PPMD if c.props.len() >= 5 => u32::from_le_bytes(c.props[1..5].try_into().unwrap()) as u64,
                _ => 0,
            })
            .sum::<u64>()
            + (1 << 20)
    }

    /// Whether every coder is one we can run.
    pub(crate) fn supported(&self) -> bool {
        self.main_out().is_some()
            && self.coders.iter().all(|c| {
                matches!(
                    c.id.as_slice(),
                    COPY | LZMA | LZMA2 | PPMD | BCJ | BCJ2 | PPC | IA64 | ARM | ARMT | SPARC | ARM64 | RISCV | DELTA | AES | DEFLATE | DEFLATE64 | BZIP2 | ZSTD
                )
            })
    }
}

const COPY: &[u8] = &[0x00];
const DELTA: &[u8] = &[0x03];
const LZMA2: &[u8] = &[0x21];
const ARM64: &[u8] = &[0x0A];
const RISCV: &[u8] = &[0x0B];
const LZMA: &[u8] = &[0x03, 0x01, 0x01];
const BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
const BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
const PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
const IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
const ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
const ARMT: &[u8] = &[0x03, 0x03, 0x07, 0x01];
const SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
const PPMD: &[u8] = &[0x03, 0x04, 0x01];
const DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
const DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
const BZIP2: &[u8] = &[0x04, 0x02, 0x02];
const ZSTD: &[u8] = &[0x04, 0xF7, 0x11, 0x01];
const AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

fn lzma2_dict(p: u8) -> u32 {
    if p >= 40 {
        return u32::MAX;
    }
    (2 | (p as u32 & 1)) << (p / 2 + 11)
}

/// Directory of a 7z archive.
pub(crate) struct Directory {
    pub entries: Vec<Entry>,
    pub folders: Vec<Folder>,
}

/// Byte-slice reader for header structures.
struct Buf<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Buf<'a> {
    fn u8(&mut self) -> Result<u8> {
        let v = *self.b.get(self.i).ok_or(Error::Corrupt("7z header truncated"))?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Corrupt("7z header truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// 7z's variable-length number: leading one bits of the first byte count extra bytes.
    fn num(&mut self) -> Result<u64> {
        let first = self.u8()? as u64;
        let mut mask = 0x80u64;
        let mut v = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                return Ok(v | ((first & (mask - 1)) << (8 * i)));
            }
            v |= (self.u8()? as u64) << (8 * i);
            mask >>= 1;
        }
        Ok(v)
    }
    /// A count used to size allocations: bounded by what's left of the header.
    fn count(&mut self) -> Result<usize> {
        let n = self.num()?;
        if n > (self.b.len() - self.i) as u64 * 8 + 64 {
            return Err(Error::Corrupt("7z count"));
        }
        Ok(n as usize)
    }
    fn bits(&mut self, n: usize) -> Result<Vec<bool>> {
        let mut out = Vec::with_capacity(n);
        let (mut cur, mut mask) = (0u8, 0u8);
        for _ in 0..n {
            if mask == 0 {
                cur = self.u8()?;
                mask = 0x80;
            }
            out.push(cur & mask != 0);
            mask >>= 1;
        }
        Ok(out)
    }
    /// "All defined" byte, then a bit vector if not.
    fn defined(&mut self, n: usize) -> Result<Vec<bool>> {
        if self.u8()? != 0 { Ok(vec![true; n]) } else { self.bits(n) }
    }
}

const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_ADDITIONAL_STREAMS: u8 = 0x03;
const K_MAIN_STREAMS: u8 = 0x04;
const K_FILES: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_NAME: u8 = 0x11;
const K_MTIME: u8 = 0x14;
const K_ATTRIBUTES: u8 = 0x15;
const K_ENCODED_HEADER: u8 = 0x17;
const K_DUMMY: u8 = 0x19;

#[derive(Default)]
struct Streams {
    folders: Vec<Folder>,
    /// per folder: substream sizes and CRCs
    sub_sizes: Vec<Vec<u64>>,
    sub_crcs: Vec<Vec<Option<u32>>>,
}

fn read_streams(b: &mut Buf, base: u64) -> Result<Streams> {
    let mut s = Streams::default();
    let mut pack_pos = 0u64;
    let mut pack_sizes = Vec::new();
    loop {
        match b.u8()? {
            K_END => break,
            K_PACK_INFO => {
                pack_pos = b.num()?;
                let n = b.count()?;
                loop {
                    match b.u8()? {
                        K_END => break,
                        K_SIZE => pack_sizes = (0..n).map(|_| b.num()).collect::<Result<_>>()?,
                        K_CRC => {
                            let d = b.defined(n)?;
                            for x in d {
                                if x {
                                    b.u32()?;
                                }
                            }
                        }
                        _ => return Err(Error::Corrupt("7z pack info")),
                    }
                }
            }
            K_UNPACK_INFO => {
                if b.u8()? != K_FOLDER {
                    return Err(Error::Corrupt("7z unpack info"));
                }
                let n = b.count()?;
                if b.u8()? != 0 {
                    return Err(Error::Unsupported("7z external folders"));
                }
                for _ in 0..n {
                    s.folders.push(read_folder(b)?);
                }
                if b.u8()? != K_UNPACK_SIZE {
                    return Err(Error::Corrupt("7z unpack sizes"));
                }
                for f in &mut s.folders {
                    let outs: usize = f.coders.iter().map(|c| c.outs).sum();
                    f.sizes = (0..outs).map(|_| b.num()).collect::<Result<_>>()?;
                }
                loop {
                    match b.u8()? {
                        K_END => break,
                        K_CRC => {
                            let d = b.defined(s.folders.len())?;
                            for (f, x) in s.folders.iter_mut().zip(d) {
                                if x {
                                    f.crc = Some(b.u32()?);
                                }
                            }
                        }
                        _ => return Err(Error::Corrupt("7z unpack info")),
                    }
                }
            }
            K_SUBSTREAMS => {
                let mut counts = vec![1usize; s.folders.len()];
                let mut t = b.u8()?;
                if t == K_NUM_UNPACK {
                    for c in &mut counts {
                        *c = b.count()?;
                    }
                    t = b.u8()?;
                }
                for (i, &c) in counts.iter().enumerate() {
                    let total = s.folders[i].size();
                    let mut sizes = Vec::with_capacity(c);
                    if c > 0 {
                        let mut sum = 0u64;
                        if t == K_SIZE {
                            for _ in 1..c {
                                let v = b.num()?;
                                sum = sum.checked_add(v).ok_or(Error::Corrupt("7z sizes"))?;
                                sizes.push(v);
                            }
                        }
                        sizes.push(total.checked_sub(sum).ok_or(Error::Corrupt("7z sizes"))?);
                    }
                    s.sub_sizes.push(sizes);
                }
                if t == K_SIZE {
                    t = b.u8()?;
                }
                // CRCs: one per substream whose CRC isn't already the folder's
                s.sub_crcs = counts.iter().map(|&c| vec![None; c]).collect();
                for (i, f) in s.folders.iter().enumerate() {
                    if counts[i] == 1 {
                        s.sub_crcs[i][0] = f.crc;
                    }
                }
                loop {
                    match t {
                        K_END => break,
                        K_CRC => {
                            let need: Vec<(usize, usize)> = (0..s.folders.len())
                                .filter(|&i| !(counts[i] == 1 && s.folders[i].crc.is_some()))
                                .flat_map(|i| (0..counts[i]).map(move |k| (i, k)))
                                .collect();
                            let d = b.defined(need.len())?;
                            for ((i, k), x) in need.into_iter().zip(d) {
                                if x {
                                    s.sub_crcs[i][k] = Some(b.u32()?);
                                }
                            }
                        }
                        _ => return Err(Error::Corrupt("7z substreams")),
                    }
                    t = b.u8()?;
                }
            }
            _ => return Err(Error::Corrupt("7z streams info")),
        }
    }
    if s.sub_sizes.is_empty() {
        // no substream info: one stream per folder
        s.sub_sizes = s.folders.iter().map(|f| vec![f.size()]).collect();
        s.sub_crcs = s.folders.iter().map(|f| vec![f.crc]).collect();
    }
    // packed stream positions
    let mut at = base + 32 + pack_pos;
    let mut next = 0usize;
    for f in &mut s.folders {
        for _ in 0..f.packed.len() {
            let size = *pack_sizes.get(next).ok_or(Error::Corrupt("7z packed streams"))?;
            f.pack.push((at, size));
            at += size;
            next += 1;
        }
    }
    Ok(s)
}

fn read_folder(b: &mut Buf) -> Result<Folder> {
    let n = b.count()?;
    if n == 0 || n > 64 {
        return Err(Error::Corrupt("7z coders"));
    }
    let mut coders = Vec::with_capacity(n);
    for _ in 0..n {
        let flag = b.u8()?;
        if flag & 0x80 != 0 {
            return Err(Error::Unsupported("7z alternative coders"));
        }
        let id = b.take((flag & 0x0F) as usize)?.to_vec();
        let (ins, outs) = if flag & 0x10 != 0 { (b.count()?, b.count()?) } else { (1, 1) };
        if ins > 64 || outs > 64 {
            return Err(Error::Corrupt("7z coder streams"));
        }
        let props = if flag & 0x20 != 0 {
            let len = b.count()?;
            b.take(len)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(Coder { id, ins, outs, props });
    }
    let total_out: usize = coders.iter().map(|c| c.outs).sum();
    let total_in: usize = coders.iter().map(|c| c.ins).sum();
    if total_out == 0 {
        return Err(Error::Corrupt("7z folder"));
    }
    let binds: Vec<(usize, usize)> = (0..total_out - 1).map(|_| Ok((b.count()?, b.count()?))).collect::<Result<_>>()?;
    let npacked = total_in.checked_sub(binds.len()).ok_or(Error::Corrupt("7z folder streams"))?;
    let packed = if npacked == 1 {
        (0..total_in).filter(|i| !binds.iter().any(|&(x, _)| x == *i)).take(1).collect()
    } else {
        (0..npacked).map(|_| b.count()).collect::<Result<_>>()?
    };
    Ok(Folder { coders, binds, packed, sizes: Vec::new(), crc: None, pack: Vec::new() })
}

/// Reads the archive's directory. `password` (UTF-8) opens encrypted headers.
pub(crate) fn read_directory(path: &PathBuf, password: Option<&str>, keys: &KeyCache) -> Result<Directory> {
    let mut f = BufReader::new(File::open(path)?);
    let mut sh = [0u8; 32];
    f.read_exact(&mut sh)?;
    if &sh[..6] != SIGNATURE {
        return Err(Error::NotArchive);
    }
    let next_off = u64::from_le_bytes(sh[12..20].try_into().unwrap());
    let next_len = u64::from_le_bytes(sh[20..28].try_into().unwrap());
    let next_crc = u32::from_le_bytes(sh[28..32].try_into().unwrap());
    if crc32fast::hash(&sh[12..32]) != u32::from_le_bytes(sh[8..12].try_into().unwrap()) {
        return Err(Error::Corrupt("7z start header checksum"));
    }
    let file_len = f.seek(SeekFrom::End(0))?;
    if next_len == 0 {
        return Ok(Directory { entries: Vec::new(), folders: Vec::new() }); // empty archive
    }
    if next_off.checked_add(32 + next_len).is_none_or(|e| e > file_len) || next_len > 1 << 30 {
        return Err(Error::Corrupt("7z header position"));
    }
    let mut header = vec![0u8; next_len as usize];
    f.seek(SeekFrom::Start(32 + next_off))?;
    f.read_exact(&mut header)?;
    if crc32fast::hash(&header) != next_crc {
        return Err(Error::Corrupt("7z header checksum"));
    }
    // a packed (and maybe encrypted) header: decode it first, possibly more than once
    for _ in 0..4 {
        if header.first() != Some(&K_ENCODED_HEADER) {
            break;
        }
        let mut b = Buf { b: &header, i: 1 };
        let s = read_streams(&mut b, 0)?;
        let folder = s.folders.first().ok_or(Error::Corrupt("7z encoded header"))?;
        if !folder.supported() {
            return Err(Error::Unsupported("7z header coder"));
        }
        let size = folder.size();
        if size > 1 << 30 {
            return Err(Error::Corrupt("7z header size"));
        }
        let mut out = Vec::with_capacity(size as usize);
        // with encrypted names, garbage anywhere here means the password is wrong
        let wrong = |e: Error| if folder.encrypted() && matches!(e, Error::Corrupt(_)) { Error::BadPassword } else { e };
        let r = decoder(path, folder, password, keys, &Ctx::SERIAL).map_err(wrong)?;
        r.take(size).read_to_end(&mut out).map_err(|e| io_err(e, folder.encrypted()))?;
        if folder.crc.is_some_and(|c| c != crc32fast::hash(&out)) {
            return Err(if folder.encrypted() { Error::BadPassword } else { Error::Corrupt("7z header checksum") });
        }
        header = out;
    }
    let mut b = Buf { b: &header, i: 0 };
    if b.u8()? != K_HEADER {
        return Err(Error::Corrupt("7z header"));
    }
    let mut streams = Streams::default();
    let mut entries: Vec<Entry> = Vec::new();
    loop {
        match b.u8()? {
            K_END => break,
            K_ARCHIVE_PROPERTIES => loop {
                let t = b.u8()?;
                if t == K_END {
                    break;
                }
                let n = b.count()?;
                b.take(n)?;
            },
            K_ADDITIONAL_STREAMS => {
                read_streams(&mut b, 0)?;
            }
            K_MAIN_STREAMS => streams = read_streams(&mut b, 0)?,
            K_FILES => entries = read_files(&mut b, &streams)?,
            _ => return Err(Error::Corrupt("7z header")),
        }
    }
    Ok(Directory { entries, folders: streams.folders })
}

fn read_files(b: &mut Buf, s: &Streams) -> Result<Vec<Entry>> {
    let n = b.count()?;
    let mut empty_stream = vec![false; n];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut mtimes: Vec<Option<u64>> = vec![None; n];
    let mut attrs: Vec<Option<u32>> = vec![None; n];
    loop {
        let t = b.u8()?;
        if t == K_END {
            break;
        }
        let size = b.num()? as usize;
        let mut p = Buf { b: b.take(size)?, i: 0 };
        match t {
            K_EMPTY_STREAM => empty_stream = p.bits(n)?,
            K_EMPTY_FILE => empty_file = p.bits(empty_stream.iter().filter(|&&x| x).count())?,
            K_NAME => {
                if p.u8()? != 0 {
                    return Err(Error::Unsupported("7z external names"));
                }
                let raw = &p.b[p.i..];
                let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                names = units.split(|&u| u == 0).take(n).map(String::from_utf16_lossy).collect();
            }
            K_MTIME => {
                let d = p.defined(n)?;
                if p.u8()? != 0 {
                    return Err(Error::Unsupported("7z external times"));
                }
                for (i, x) in d.into_iter().enumerate() {
                    if x {
                        mtimes[i] = Some(p.u64()?);
                    }
                }
            }
            K_ATTRIBUTES => {
                let d = p.defined(n)?;
                if p.u8()? != 0 {
                    return Err(Error::Unsupported("7z external attributes"));
                }
                for (i, x) in d.into_iter().enumerate() {
                    if x {
                        attrs[i] = Some(p.u32()?);
                    }
                }
            }
            K_DUMMY | _ => {} // times we don't use, anti items, comments, padding
        }
    }
    // files with data take the folders' substreams in order
    let mut folder = 0usize;
    let mut sub = 0usize;
    let mut offset = 0u64;
    let mut empty_k = 0usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let name = names.get(i).cloned().unwrap_or_default().replace('\\', "/");
        let attr = attrs[i].unwrap_or(0);
        let mut e = Entry {
            raw_name: name.as_bytes().to_vec(),
            name,
            is_dir: false,
            size: 0,
            packed_size: 0,
            attributes: attr as u64,
            mtime: mtimes[i].map(filetime),
            dos_time: None,
            crc32: None,
            blake2sp: None,
            encrypted: false,
            is_link: attr & 0x8000 != 0 && (attr >> 16) & 0o170000 == 0o120000,
            method: 0,
            algo: 0,
            solid: false,
            dict_size: 0,
            split_before: false,
            split_after: false,
            data_offset: 0,
            crypt: None,
            parts: Vec::new(),
            zip: None,
            folder: None,
        };
        if empty_stream[i] {
            let is_file = empty_file.get(empty_k).copied().unwrap_or(false);
            empty_k += 1;
            e.is_dir = !is_file || attr & 0x10 != 0;
        } else {
            while s.sub_sizes.get(folder).is_some_and(|v| sub >= v.len()) {
                folder += 1;
                sub = 0;
                offset = 0;
            }
            let sizes = s.sub_sizes.get(folder).ok_or(Error::Corrupt("7z more files than streams"))?;
            e.size = sizes[sub];
            e.crc32 = s.sub_crcs[folder][sub];
            e.data_offset = offset;
            e.folder = Some(folder as u32);
            e.solid = sub > 0;
            let fo = &s.folders[folder];
            e.encrypted = fo.encrypted();
            if sub == 0 {
                e.packed_size = fo.pack.iter().map(|p| p.1).sum();
            }
            offset += e.size;
            sub += 1;
        }
        out.push(e);
    }
    Ok(out)
}

fn io_err(e: io::Error, encrypted: bool) -> Error {
    match e.kind() {
        // a wrong AES key makes the decoder see garbage
        _ if encrypted => Error::BadPassword,
        io::ErrorKind::UnexpectedEof => Error::Corrupt("7z data ends early"),
        io::ErrorKind::InvalidData | io::ErrorKind::Other => Error::Corrupt("bad 7z data"),
        _ => Error::Io(e),
    }
}

/// Derived AES keys by (salt, cycles), shared by a worker pool.
pub(crate) type KeyCache = std::sync::Mutex<Vec<(Vec<u8>, u8, [u8; 32])>>;

fn aes_key(props: &[u8], password: &str, keys: &KeyCache) -> Result<([u8; 32], [u8; 16])> {
    if props.len() < 2 {
        return Err(Error::Corrupt("7z AES properties"));
    }
    let (b0, b1) = (props[0], props[1]);
    let cycles = b0 & 63;
    let iv_len = (((b0 >> 6) & 1) + (b1 & 15)) as usize;
    let salt_len = (((b0 >> 7) & 1) + (b1 >> 4)) as usize;
    if 2 + salt_len + iv_len > props.len() || iv_len > 16 {
        return Err(Error::Corrupt("7z AES properties"));
    }
    let salt = &props[2..2 + salt_len];
    let mut iv = [0u8; 16];
    iv[..iv_len].copy_from_slice(&props[2 + salt_len..2 + salt_len + iv_len]);
    let pw: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if let Some((_, _, k)) = keys.lock().unwrap().iter().find(|(s, c, _)| s == salt && *c == cycles) {
        return Ok((*k, iv));
    }
    let key = if cycles == 0x3F {
        let mut k = [0u8; 32];
        k[..salt_len].copy_from_slice(salt);
        let n = pw.len().min(32 - salt_len);
        k[salt_len..salt_len + n].copy_from_slice(&pw[..n]);
        k
    } else {
        if cycles > 24 {
            return Err(Error::Corrupt("7z AES iteration count"));
        }
        // one SHA-256 over (salt, password, counter) repeated 2^cycles times
        let mut sha = Sha256::new();
        let mut buf = Vec::with_capacity((salt.len() + pw.len() + 8) * 64);
        let mut counter = 0u64;
        let rounds = 1u64 << cycles;
        while counter < rounds {
            buf.clear();
            for _ in 0..64.min(rounds - counter) {
                buf.extend_from_slice(salt);
                buf.extend_from_slice(&pw);
                buf.extend_from_slice(&counter.to_le_bytes());
                counter += 1;
            }
            sha.update(&buf);
        }
        sha.finalize().into()
    };
    keys.lock().unwrap().push((salt.to_vec(), cycles, key));
    Ok((key, iv))
}

/// Opens one packed stream of a folder.
fn packed_stream(path: &PathBuf, (at, size): (u64, u64)) -> io::Result<Box<dyn Read + Send>> {
    let mut f = BufReader::with_capacity(1 << 20, File::open(path)?);
    f.seek(SeekFrom::Start(at))?;
    Ok(Box::new(f.take(size)))
}

/// A reader producing the folder's main output.
pub(crate) fn decoder(path: &PathBuf, folder: &Folder, password: Option<&str>, keys: &KeyCache, ctx: &Ctx) -> Result<Box<dyn Read + Send>> {
    let out = folder.main_out().ok_or(Error::Corrupt("7z folder"))?;
    stream_for_out(path, folder, out, password, keys, ctx, 0)
}

/// How much of the machine a folder's decoder may use.
#[derive(Clone, Copy)]
pub(crate) struct Ctx {
    pub threads: usize,
    pub priority: crate::cpu::Priority,
    /// Memory for decoded pieces waiting their turn.
    pub budget: u64,
}

impl Ctx {
    pub(crate) const SERIAL: Ctx = Ctx { threads: 1, priority: crate::cpu::Priority::Low, budget: 0 };
}

/// Reader for coder output stream `out` (recursing through the bind pairs).
fn stream_for_out(path: &PathBuf, f: &Folder, out: usize, pw: Option<&str>, keys: &KeyCache, ctx: &Ctx, depth: u32) -> Result<Box<dyn Read + Send>> {
    if depth > 32 {
        return Err(Error::Corrupt("7z coder graph"));
    }
    // which coder produces `out`, and where its inputs start
    let (mut first_in, mut first_out) = (0usize, 0usize);
    let mut ci = None;
    for (i, c) in f.coders.iter().enumerate() {
        if out < first_out + c.outs {
            ci = Some(i);
            break;
        }
        first_in += c.ins;
        first_out += c.outs;
    }
    let ci = ci.ok_or(Error::Corrupt("7z coder graph"))?;
    let c = &f.coders[ci];
    if c.outs != 1 {
        return Err(Error::Unsupported("7z coder with several outputs"));
    }
    let size = *f.sizes.get(out).ok_or(Error::Corrupt("7z sizes"))?;
    let mut inputs: Vec<Box<dyn Read + Send>> = Vec::with_capacity(c.ins);
    // the packed stream behind each input, when it reads one directly
    let mut direct: Vec<Option<(u64, u64)>> = Vec::with_capacity(c.ins);
    for k in 0..c.ins {
        let in_index = first_in + k;
        let r = if let Some(&(_, o)) = f.binds.iter().find(|&&(i, _)| i == in_index) {
            direct.push(None);
            stream_for_out(path, f, o, pw, keys, ctx, depth + 1)?
        } else {
            let p = f.packed.iter().position(|&x| x == in_index).ok_or(Error::Corrupt("7z packed stream index"))?;
            let pack = *f.pack.get(p).ok_or(Error::Corrupt("7z packed streams"))?;
            direct.push(Some(pack));
            packed_stream(path, pack)?
        };
        inputs.push(r);
    }
    let bad = |_| Error::Corrupt("7z coder properties");
    let one = |inputs: &mut Vec<Box<dyn Read + Send>>| inputs.pop().ok_or(Error::Corrupt("7z coder inputs"));
    let r: Box<dyn Read + Send> = match c.id.as_slice() {
        COPY => one(&mut inputs)?,
        LZMA => {
            if c.props.len() < 5 {
                return Err(Error::Corrupt("7z LZMA properties"));
            }
            let dict = u32::from_le_bytes(c.props[1..5].try_into().unwrap());
            if old_lzma() {
                Box::new(lzma_rust2::LzmaReader::new_with_props(one(&mut inputs)?, size, c.props[0], dict, None).map_err(bad)?)
            } else {
                Box::new(crate::lzma::LzmaReader::new(one(&mut inputs)?, c.props[0], dict, size).map_err(|_| Error::Corrupt("7z LZMA properties"))?)
            }
        }
        LZMA2 => {
            let p = *c.props.first().ok_or(Error::Corrupt("7z LZMA2 properties"))?;
            let dict = lzma2_dict(p);
            // a big stream with several dictionary resets decodes piece by piece in parallel
            if let (Some(pack), true) = (direct[0], ctx.threads > 1 && size >= par_min()) {
                if let Some(par) = ParLzma2::new(path, pack, dict, ctx)? {
                    return Ok(Box::new(par));
                }
            }
            lzma2(one(&mut inputs)?, dict)
        }
        PPMD => {
            if c.props.len() < 5 {
                return Err(Error::Corrupt("7z PPMd properties"));
            }
            let order = c.props[0] as u32;
            let mem = u32::from_le_bytes(c.props[1..5].try_into().unwrap());
            Box::new(ppmd_rust::Ppmd7Decoder::new(one(&mut inputs)?, order, mem).map_err(|_| Error::Corrupt("7z PPMd properties"))?.take(size))
        }
        BCJ => Box::new(lzma_rust2::filter::bcj::BcjReader::new_x86(one(&mut inputs)?, 0)),
        PPC => Box::new(lzma_rust2::filter::bcj::BcjReader::new_ppc(one(&mut inputs)?, 0)),
        IA64 => Box::new(lzma_rust2::filter::bcj::BcjReader::new_ia64(one(&mut inputs)?, 0)),
        ARM => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm(one(&mut inputs)?, 0)),
        ARMT => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm_thumb(one(&mut inputs)?, 0)),
        SPARC => Box::new(lzma_rust2::filter::bcj::BcjReader::new_sparc(one(&mut inputs)?, 0)),
        ARM64 => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm64(one(&mut inputs)?, 0)),
        RISCV => Box::new(lzma_rust2::filter::bcj::BcjReader::new_riscv(one(&mut inputs)?, 0)),
        DELTA => {
            let dist = c.props.first().map_or(1, |&d| d as usize + 1);
            Box::new(lzma_rust2::filter::delta::DeltaReader::new(one(&mut inputs)?, dist))
        }
        BCJ2 => {
            if inputs.len() != 4 {
                return Err(Error::Corrupt("7z BCJ2 inputs"));
            }
            Box::new(lzma_rust2::filter::bcj2::Bcj2Reader::new(inputs, size))
        }
        DEFLATE => Box::new(flate2::read::DeflateDecoder::new(one(&mut inputs)?)),
        DEFLATE64 => Box::new(deflate64::Deflate64Decoder::new(one(&mut inputs)?)),
        BZIP2 => Box::new(bzip2::read::BzDecoder::new(one(&mut inputs)?)),
        ZSTD => Box::new(zstd::stream::read::Decoder::new(one(&mut inputs)?).map_err(Error::Io)?),
        AES => {
            let pw = pw.ok_or(Error::NeedPassword)?;
            let (key, iv) = aes_key(&c.props, pw, keys)?;
            Box::new(crate::crypto::DecryptReader::new(one(&mut inputs)?, &key, &iv))
        }
        _ => return Err(Error::Unsupported("7z coder")),
    };
    Ok(r)
}

/// Decodes a folder, handing out its members' bytes: `each(index_in_folder, size)` is
/// called before each substream and returns the sink for it.
pub(crate) fn decode_folder(
    path: &PathBuf,
    folder: &Folder,
    password: Option<&str>,
    keys: &KeyCache,
    ctx: &Ctx,
    sizes: &[u64],
    mut member: impl FnMut(usize, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let r = decoder(path, folder, password, keys, ctx)?;
    // big folders: decode ahead on another thread while the caller writes
    let r: Box<dyn Read> = if folder.size() >= (4 << 20).min(par_min()) && ctx.threads > 1 { Box::new(ReadAhead::new(r, ctx.priority)) } else { r };
    let mut r = r.take(folder.size());
    for (i, &n) in sizes.iter().enumerate() {
        let mut part = (&mut r).take(n);
        member(i, &mut part)?;
        // whatever the sink didn't read
        io::copy(&mut part, &mut io::sink()).map_err(|e| io_err(e, folder.encrypted()))?;
    }
    Ok(())
}

pub(crate) fn map_io(e: io::Error, encrypted: bool) -> Error {
    io_err(e, encrypted)
}

/// Where an LZMA2 stream can be cut into independently decodable pieces: (packed offset,
/// unpacked offset) of every chunk that resets the dictionary, plus the totals at the end.
/// Reads only chunk headers.
pub(crate) fn lzma2_resets(r: &mut dyn Read) -> io::Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let (mut pk, mut un) = (0u64, 0u64);
    let skip = |r: &mut dyn Read, n: u64| io::copy(&mut r.take(n), &mut io::sink());
    loop {
        let mut c = [0u8; 1];
        if r.read(&mut c)? == 0 {
            break;
        }
        let c = c[0];
        if c == 0 {
            break;
        }
        let (dict_reset, head, unpacked, packed);
        if c == 1 || c == 2 {
            let mut h = [0u8; 2];
            r.read_exact(&mut h)?;
            let n = u16::from_be_bytes(h) as u64 + 1;
            (dict_reset, head, unpacked, packed) = (c == 1, 3, n, n);
        } else if c >= 0x80 {
            let mut h = [0u8; 4];
            r.read_exact(&mut h)?;
            let u = (((c & 0x1F) as u64) << 16 | u16::from_be_bytes([h[0], h[1]]) as u64) + 1;
            let p = u16::from_be_bytes([h[2], h[3]]) as u64 + 1;
            let props = ((c >> 5) & 3) >= 2;
            if props {
                skip(r, 1)?;
            }
            (dict_reset, head, unpacked, packed) = ((c >> 5) & 3 == 3, 5 + props as u64, u, p);
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "LZMA2 control byte"));
        }
        if dict_reset {
            out.push((pk, un));
        }
        skip(r, packed)?;
        pk += head + packed;
        un += unpacked;
    }
    out.push((pk, un));
    Ok(out)
}

#[doc(hidden)]
pub fn debug_segments(path: &std::path::Path) -> Result<Vec<String>> {
    let d = read_directory(&path.to_path_buf(), None, &std::sync::Mutex::new(Vec::new()))?;
    let mut lines = Vec::new();
    for (i, f) in d.folders.iter().enumerate() {
        let ids: Vec<String> = f.coders.iter().map(|c| format!("{:02x?}", c.id)).collect();
        let mut seg = String::new();
        if let Some(lz) = f.coders.iter().position(|c| c.id == LZMA2) {
            // the LZMA2 coder's first input, when it reads a packed stream
            let first_in: usize = f.coders[..lz].iter().map(|c| c.ins).sum();
            if let Some(p) = f.packed.iter().position(|&x| x == first_in) {
                let mut r = packed_stream(&path.to_path_buf(), f.pack[p])?;
                let s = lzma2_resets(&mut *r)?;
                seg = format!("{} independent pieces, unpacked {:.1} MB", s.len() - 1, s.last().unwrap().1 as f64 / 1e6);
            }
        }
        lines.push(format!("folder {i}: coders {ids:?}, {:.1} MB -> {:.1} MB; {seg}", f.pack.iter().map(|p| p.1).sum::<u64>() as f64 / 1e6, f.size() as f64 / 1e6));
    }
    Ok(lines)
}

/// LZMA2 streams below this size decode on one thread (`RARCHIVE_PIPE_MIN` overrides it, for
/// tests, like the RAR block-parallel threshold).
fn par_min() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("RARCHIVE_PIPE_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(16 << 20))
}

/// One independently decodable piece of an LZMA2 stream: packed offset and length (in the
/// packed stream), unpacked length.
#[derive(Clone, Copy)]
struct Piece {
    pk: u64,
    pk_len: u64,
    un_len: u64,
}

/// Shared between the reader and its helper threads.
struct ParState {
    path: PathBuf,
    pack_at: u64,
    dict: u32,
    pieces: Vec<Piece>,
    /// next piece a helper takes (piece 0 is the reader's own)
    next: std::sync::atomic::AtomicUsize,
    /// decoded pieces waiting to be read
    slots: Vec<std::sync::Mutex<Option<io::Result<Vec<u8>>>>>,
    ready: std::sync::Condvar,
    ready_lock: std::sync::Mutex<()>,
    /// (bytes held, next piece allowed to reserve): reservations go in piece order, so the
    /// piece the reader waits for is never starved by later ones
    budget: std::sync::Mutex<(u64, usize)>,
    freed: std::sync::Condvar,
    max: u64,
    cancel: std::sync::atomic::AtomicBool,
}

/// Decodes an LZMA2 stream with dictionary resets on several threads: piece 0 streams
/// through the reader; later pieces are decoded ahead by helper threads (low priority,
/// within the memory budget) and handed over in order.
struct ParLzma2 {
    st: std::sync::Arc<ParState>,
    cur: usize,
    inline: Option<Box<dyn Read + Send>>,
    buf: Vec<u8>,
    pos: usize,
    held: u64,
}

impl ParLzma2 {
    fn new(path: &PathBuf, pack: (u64, u64), dict: u32, ctx: &Ctx) -> Result<Option<ParLzma2>> {
        let mut scan = packed_stream(path, pack)?;
        let Ok(resets) = lzma2_resets(&mut *scan) else { return Ok(None) };
        if resets.len() < 3 || resets[0] != (0, 0) {
            return Ok(None);
        }
        let pieces: Vec<Piece> = resets.windows(2).map(|w| Piece { pk: w[0].0, pk_len: w[1].0 - w[0].0, un_len: w[1].1 - w[0].1 }).collect();
        let n = pieces.len();
        let st = std::sync::Arc::new(ParState {
            path: path.clone(),
            pack_at: pack.0,
            dict,
            slots: (0..n).map(|_| std::sync::Mutex::new(None)).collect(),
            pieces,
            next: std::sync::atomic::AtomicUsize::new(1),
            ready: std::sync::Condvar::new(),
            ready_lock: std::sync::Mutex::new(()),
            budget: std::sync::Mutex::new((0, 1)),
            freed: std::sync::Condvar::new(),
            max: ctx.budget,
            cancel: std::sync::atomic::AtomicBool::new(false),
        });
        for _ in 0..ctx.threads.min(n - 1) {
            let st = st.clone();
            let prio = ctx.priority;
            std::thread::spawn(move || {
                crate::cpu::apply_priority(prio);
                helper(&st);
            });
        }
        let first = st.pieces[0];
        let inline: Box<dyn Read + Send> =
            Box::new(lzma2(Box::new(piece_input(path, pack.0, first)?), dict).take(first.un_len));
        Ok(Some(ParLzma2 { st, cur: 0, inline: Some(inline), buf: Vec::new(), pos: 0, held: 0 }))
    }
}

/// A piece's packed bytes followed by an end-of-stream byte, so the decoder stops there.
fn piece_input(path: &PathBuf, pack_at: u64, p: Piece) -> io::Result<impl Read + Send + use<>> {
    Ok(packed_stream(path, (pack_at + p.pk, p.pk_len))?.chain(io::Cursor::new([0u8])))
}

fn helper(st: &ParState) {
    use std::sync::atomic::Ordering;
    loop {
        let i = st.next.fetch_add(1, Ordering::Relaxed);
        let Some(&p) = st.pieces.get(i) else { return };
        let need = p.un_len + st.dict as u64;
        {
            let mut b = st.budget.lock().unwrap();
            while !st.cancel.load(Ordering::Relaxed) && !(b.1 == i && (b.0 == 0 || b.0 + need <= st.max)) {
                b = st.freed.wait(b).unwrap();
            }
            if st.cancel.load(Ordering::Relaxed) {
                return;
            }
            b.0 += need;
            b.1 += 1;
            st.freed.notify_all();
        }
        let r = (|| -> io::Result<Vec<u8>> {
            let mut d = lzma2(Box::new(piece_input(&st.path, st.pack_at, p)?), st.dict);
            let mut out = Vec::with_capacity(p.un_len as usize);
            let mut chunk = [0u8; 1 << 16];
            while (out.len() as u64) < p.un_len {
                if st.cancel.load(Ordering::Relaxed) {
                    return Err(io::Error::other("cancelled"));
                }
                let n = d.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Ok(out)
        })();
        *st.slots[i].lock().unwrap() = Some(r);
        let _g = st.ready_lock.lock().unwrap();
        st.ready.notify_all();
    }
}

impl Read for ParLzma2 {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(r) = self.inline.as_mut() {
                let n = r.read(out)?;
                if n > 0 {
                    return Ok(n);
                }
                self.inline = None;
                self.cur = 1;
            } else if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            } else {
                // done with the current piece: give its memory back, wait for the next
                if self.held > 0 {
                    self.buf = Vec::new();
                    self.pos = 0;
                    let mut b = self.st.budget.lock().unwrap();
                    b.0 -= self.held;
                    self.held = 0;
                    self.st.freed.notify_all();
                    self.cur += 1;
                }
                if self.cur >= self.st.pieces.len() {
                    return Ok(0);
                }
                let mut g = self.st.ready_lock.lock().unwrap();
                let data = loop {
                    if let Some(r) = self.st.slots[self.cur].lock().unwrap().take() {
                        break r;
                    }
                    g = self.st.ready.wait(g).unwrap();
                };
                drop(g);
                self.buf = data?;
                self.pos = 0;
                self.held = self.st.pieces[self.cur].un_len + self.st.dict as u64;
                if self.buf.is_empty() {
                    // an empty piece still counts
                    continue;
                }
            }
        }
    }
}

impl Drop for ParLzma2 {
    fn drop(&mut self) {
        self.st.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let _b = self.st.budget.lock().unwrap();
        self.st.freed.notify_all();
    }
}

/// Runs a decoder on its own thread, a few buffers ahead of the reader: decoding then
/// overlaps with whatever the reader does with the data (writing files).
struct ReadAhead {
    rx: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    back: std::sync::mpsc::SyncSender<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl ReadAhead {
    fn new(mut r: Box<dyn Read + Send>, priority: crate::cpu::Priority) -> ReadAhead {
        const N: usize = 4;
        const SIZE: usize = 1 << 20;
        let (tx, rx) = std::sync::mpsc::sync_channel::<io::Result<Vec<u8>>>(N);
        // used buffers come back for reuse
        let (back, spare) = std::sync::mpsc::sync_channel::<Vec<u8>>(N + 2);
        std::thread::spawn(move || {
            crate::cpu::apply_priority(priority);
            loop {
                let mut b = spare.try_recv().unwrap_or_else(|_| Vec::with_capacity(SIZE));
                b.resize(SIZE, 0);
                let mut n = 0;
                let res = loop {
                    if n == SIZE {
                        break Ok(());
                    }
                    match r.read(&mut b[n..]) {
                        Ok(0) => break Ok(()),
                        Ok(k) => n += k,
                        Err(e) => break Err(e),
                    }
                };
                b.truncate(n);
                let end = n == 0;
                let msg = match res {
                    Ok(()) => Ok(b),
                    Err(e) => Err(e),
                };
                let failed = msg.is_err();
                if tx.send(msg).is_err() || end || failed {
                    return;
                }
            }
        });
        ReadAhead { rx, back, buf: Vec::new(), pos: 0, done: false }
    }
}

impl Read for ReadAhead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.done {
                return Ok(0);
            }
            let used = std::mem::take(&mut self.buf);
            let _ = self.back.try_send(used);
            match self.rx.recv() {
                Ok(Ok(b)) => {
                    if b.is_empty() {
                        self.done = true;
                    }
                    self.buf = b;
                    self.pos = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.done = true;
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Our own LZMA2 decoder (`RARCHIVE_LZMA=old` picks lzma-rust2's, for comparisons).
fn lzma2(r: Box<dyn Read + Send>, dict: u32) -> Box<dyn Read + Send> {
    if old_lzma() { Box::new(lzma_rust2::Lzma2Reader::new(r, dict, None)) } else { Box::new(crate::lzma::Lzma2Reader::new(r, dict)) }
}

fn old_lzma() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("RARCHIVE_LZMA").is_ok_and(|v| v == "old"))
}

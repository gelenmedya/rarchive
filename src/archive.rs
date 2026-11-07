//! Archives: opening (RAR 5 headers here, ZIP in `zip`), entries, and extraction, in order
//! or in parallel.

use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use crate::cpu::Priority;
use crate::crypto;
use crate::error::{Error, Result};
use crate::rar4;
use crate::unpack5::{self, Member, MemberSink, Unpack5};
use crate::sevenz;
use crate::volume;
use crate::zip;

const SIG5: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const SIG4: &[u8; 7] = b"Rar!\x1a\x07\x00";
/// A base header is at most 2 MB (three vint bytes).
const MAX_HEADER: u64 = 2 << 20;

/// One archive member.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Path inside the archive, `/`-separated.
    pub name: String,
    /// The name as stored. For ZIP members without the UTF-8 flag `name` is decoded as
    /// code page 437; callers that know the creating PC's code page can decode this instead.
    pub raw_name: Vec<u8>,
    pub is_dir: bool,
    pub size: u64,
    pub packed_size: u64,
    pub attributes: u64,
    /// Last modification time, when stored as an absolute time.
    pub mtime: Option<std::time::SystemTime>,
    /// MS-DOS date and time (ZIP), in the creating PC's local time: callers convert it
    /// with the local time zone when `mtime` is missing.
    pub dos_time: Option<u32>,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    pub encrypted: bool,
    /// A symbolic link, junction or hard link (a redirection record): its data is not
    /// file content.
    pub is_link: bool,
    /// Compression method, in the format's own numbering (RAR: 0 stored, 1-5; ZIP: 0
    /// stored, 8 Deflate, ...).
    pub method: u16,
    /// Compression algorithm version: 0 = RAR 5, 1 = RAR 7; RAR 1.5-4: the unpack version
    /// (15, 20, 26, 29, 36).
    pub algo: u8,
    /// Continues the previous member's compression state.
    pub solid: bool,
    pub dict_size: u64,
    /// The data continues from the previous / into the next volume.
    pub split_before: bool,
    pub split_after: bool,
    /// RAR: start of the packed data. ZIP: the local header.
    pub(crate) data_offset: u64,
    /// RAR 5 encryption parameters of an encrypted member.
    pub(crate) crypt: Option<Box<crypto::Params>>,
    /// RAR: where the packed data is, volume by volume (one part unless split).
    pub(crate) parts: Vec<volume::Part>,
    /// ZIP specifics (general purpose flags, WinZip AES parameters).
    pub(crate) zip: Option<Box<zip::Extra>>,
    /// 7z: the folder (solid block) holding the data; `data_offset` is the offset in it.
    pub(crate) folder: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Rar,
    /// RAR 1.5-4.x (see `rar4`).
    Rar4,
    Zip,
    SevenZ,
}

pub struct Archive {
    /// The archive (for a volume set, its first volume).
    path: PathBuf,
    /// Every volume of the set (just `path` when there is one).
    volumes: Vec<PathBuf>,
    format: Format,
    entries: Vec<Entry>,
    solid: bool,
    volume: bool,
    priority: Priority,
    memory_budget: u64,
    password: Option<Vec<u8>>,
    /// Keys derived so far, by (salt, iteration log): deriving is deliberately slow and
    /// archives usually use one salt for everything.
    keys: std::sync::Mutex<Vec<([u8; 16], u8, std::sync::Arc<crypto::Keys>)>>,
    /// 7z folders, and keys derived for them.
    folders: Vec<sevenz::Folder>,
    sz_keys: sevenz::KeyCache,
    /// RAR 1.5-4 state (keys, salts) of such an archive.
    rar4: Option<Box<rar4::Shared>>,
}

/// Receives extracted data, file by file.
pub trait Sink {
    /// Called before a member's data. Return `false` to discard it (a solid archive still
    /// has to decode it for the members after it).
    fn begin(&mut self, entry: &Entry) -> std::io::Result<bool>;
    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Called after the data was checked against the stored checksum.
    fn end(&mut self, entry: &Entry) -> std::io::Result<()>;
}

impl Archive {
    /// Reads the archive's headers.
    pub fn open(path: impl AsRef<Path>) -> Result<Archive> {
        Self::open_with_password(path, None)
    }

    /// Reads the archive's headers; `password` opens encrypted archives (archives whose
    /// file names are encrypted need it here already).
    pub fn open_with_password(path: impl AsRef<Path>, password: Option<&str>) -> Result<Archive> {
        let path = path.as_ref().to_path_buf();
        let mut f = BufReader::with_capacity(64 << 10, File::open(&path)?);
        let mut sig = [0u8; 8];
        let n = f.read(&mut sig)?;
        let mut a = Archive {
            volumes: vec![path.clone()],
            path,
            format: Format::Rar,
            entries: Vec::new(),
            solid: false,
            volume: false,
            priority: Priority::default(),
            memory_budget: crate::cpu::memory_budget(),
            password: password.filter(|p| !p.is_empty()).map(|p| p.as_bytes().to_vec()),
            keys: std::sync::Mutex::new(Vec::new()),
            folders: Vec::new(),
            sz_keys: std::sync::Mutex::new(Vec::new()),
            rar4: None,
        };
        if n >= 6 && &sig[..6] == sevenz::SIGNATURE {
            drop(f);
            let d = sevenz::read_directory(&a.path, password.filter(|p| !p.is_empty()), &a.sz_keys)?;
            a.format = Format::SevenZ;
            // members without data (folders, empty files) first: the rest then sit in
            // folder order, each folder's members side by side
            let (mut entries, data): (Vec<Entry>, Vec<Entry>) = d.entries.into_iter().partition(|e| e.folder.is_none());
            entries.extend(data);
            a.solid = d.folders.iter().enumerate().any(|(i, _)| entries.iter().filter(|e| e.folder == Some(i as u32)).count() > 1);
            a.entries = entries;
            a.folders = d.folders;
            return Ok(a);
        }
        if n < 8 || &sig != SIG5 {
            if n >= 7 && sig[..7] == SIG4[..] {
                let o = rar4::open(&a.path, a.password.as_deref())?;
                a.format = Format::Rar4;
                (a.entries, a.solid, a.volume, a.volumes, a.path) = (o.entries, o.solid, o.volume, o.volumes, o.path);
                a.rar4 = Some(Box::new(o.shared));
                return Ok(a);
            }
            if n >= 4 && &sig[..4] == b"RE~^" {
                return Err(Error::OldFormat); // RAR 1.3 / 1.4
            }
            // ZIP is found by its directory at the end (it may have data in front)
            drop(f);
            a.format = Format::Zip;
            // numbered split parts (x.zip.001, x.zip.002, ...) are one file cut in pieces
            if let Some(parts) = volume::numbered_parts(&a.path) {
                a.volumes = parts;
                a.path = a.volumes[0].clone();
            }
            let mut src = volume::open_concat(&a.volumes)?;
            let mut d = zip::read_directory(&mut *src, None)?;
            if d.volume && d.disk > 0 {
                // spanned (x.z01, ..., x.zip): read all disks as one stream
                if let Some(disks) = volume::spanned_parts(&a.path, d.disk + 1) {
                    let mut bases = Vec::with_capacity(disks.len());
                    let mut at = 0u64;
                    for p in &disks {
                        bases.push(at);
                        at += std::fs::metadata(p)?.len();
                    }
                    let mut src = volume::open_concat(&disks)?;
                    d = zip::read_directory(&mut *src, Some(&bases))?;
                    a.volumes = disks;
                }
            }
            a.entries = d.entries;
            a.volume = d.volume;
            return Ok(a);
        }
        // A volume set is read from its first volume, whichever one was opened.
        let mut more = a.read_volume(&mut f, 0)?;
        if a.volume {
            if let Some((naming, dir, k)) = volume::Naming::of(&a.path) {
                if k != 0 {
                    let first = dir.join(naming.name(0));
                    let mut f = open_rar5(&first).map_err(|_| Error::Corrupt("the first volume of the set is missing"))?;
                    a.entries.clear();
                    a.path = first.clone();
                    a.volumes = vec![first];
                    more = a.read_volume(&mut f, 0)?;
                }
                let mut k = 1;
                while more {
                    let p = dir.join(naming.name(k));
                    // a missing volume leaves its members incomplete (listed, not extractable)
                    let Ok(mut f) = open_rar5(&p) else { break };
                    a.volumes.push(p);
                    more = a.read_volume(&mut f, k as u32)?;
                    k += 1;
                }
            }
        }
        Ok(a)
    }

    /// Reads one RAR 5 volume's headers (`f` just past the signature). Members continued
    /// from the previous volume are merged into the entry they continue. Returns whether
    /// the volume says another one follows.
    fn read_volume(&mut self, f: &mut BufReader<File>, vol: u32) -> Result<bool> {
        let mut pos = 8u64;
        let mut body = Vec::new();
        let mut header_key: Option<std::sync::Arc<crypto::Keys>> = None;
        loop {
            let Some(used) = read_header(f, header_key.as_deref(), &mut body)? else { return Ok(false) };
            pos += used;
            let size = body.len() as u64;
            let mut c = Cursor { b: &body, i: 0 };
            let kind = c.vint()?;
            let flags = c.vint()?;
            let extra_size = if flags & 1 != 0 { c.vint()? } else { 0 };
            let data_size = if flags & 2 != 0 { c.vint()? } else { 0 };
            let extra_start = (size).checked_sub(extra_size).ok_or(Error::Corrupt("extra area size"))? as usize;
            match kind {
                1 => {
                    let aflags = c.vint()?;
                    self.volume |= aflags & 1 != 0;
                    self.solid |= aflags & 4 != 0;
                }
                2 => {
                    let mut e = parse_file(&mut c, &body[extra_start..])?;
                    let part = volume::Part { vol, offset: pos, size: data_size };
                    e.packed_size = data_size;
                    e.data_offset = pos;
                    e.split_after = flags & 0x10 != 0;
                    let continued = flags & 8 != 0;
                    match self.entries.last_mut().filter(|p| continued && p.split_after && p.name == e.name) {
                        Some(prev) => {
                            prev.parts.push(part);
                            prev.packed_size += data_size;
                            prev.split_after = e.split_after;
                            if !e.split_after {
                                // the last part carries the whole file's checksums
                                prev.crc32 = e.crc32;
                                prev.blake2sp = e.blake2sp;
                            }
                        }
                        None => {
                            e.split_before = continued; // continues a part we don't have
                            e.parts = vec![part];
                            self.entries.push(e);
                        }
                    }
                }
                3 => {} // service header (comment, quick open, ...)
                4 => {
                    // archive encryption: every following header is encrypted
                    if c.vint()? != 0 {
                        return Err(Error::Unsupported("encryption version"));
                    }
                    let eflags = c.vint()?;
                    let kdf_log = c.take(1)?[0];
                    let salt: [u8; 16] = c.take(16)?.try_into().unwrap();
                    let check = if eflags & 1 != 0 { Some(c.take(12)?.try_into().unwrap()) } else { None };
                    let p = crypto::Params { kdf_log, salt, iv: [0; 16], check, mac_checksums: false };
                    header_key = Some(self.keys_for(&p)?);
                }
                5 => {
                    // end of archive: flag 1 = more volumes follow
                    return Ok(c.vint().unwrap_or(0) & 1 != 0);
                }
                _ => {
                    if flags & 4 == 0 {
                        // unknown header that may not be skipped
                        return Err(Error::Unsupported("unknown header type"));
                    }
                }
            }
            if data_size > 0 {
                f.seek_relative(data_size as i64)?;
                pos += data_size;
            }
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_solid(&self) -> bool {
        self.solid
    }

    /// Whether this build can extract every member (no encryption, no volume set).
    pub fn can_extract(&self) -> bool {
        self.unsupported().is_none()
    }

    /// Why [`can_extract`](Self::can_extract) is false: the first member this build can't
    /// extract, and the reason. `None` when everything can be extracted.
    pub fn unsupported(&self) -> Option<(&Entry, Error)> {
        self.entries.iter().find_map(|e| {
            let why = match self.format {
                Format::Rar | Format::Rar4 if e.is_dir => None,
                Format::Rar | Format::Rar4 if e.encrypted && e.crypt.is_none() => Some(Error::Unsupported("old RAR encryption")),
                Format::Rar | Format::Rar4 if e.split_before || e.split_after => Some(Error::Unsupported("missing volume")),
                Format::Rar4 if !rar4::supported(e) => Some(Error::Unsupported("RAR compression method")),
                Format::Zip if self.volume => Some(Error::Unsupported("ZIP volume set")),
                Format::Zip if !zip::supported(e) => Some(Error::Unsupported("ZIP compression or encryption method")),
                Format::SevenZ if !e.folder.is_none_or(|f| self.folders.get(f as usize).is_some_and(|f| f.supported())) => {
                    Some(Error::Unsupported("7z coder"))
                }
                _ => None,
            };
            why.map(|w| (e, w))
        })
    }

    /// Whether extracting needs a password (some member is encrypted).
    pub fn needs_password(&self) -> bool {
        self.entries.iter().any(|e| e.encrypted)
    }

    /// Keys for encryption parameters `p`, derived once per salt.
    fn keys_for(&self, p: &crypto::Params) -> Result<std::sync::Arc<crypto::Keys>> {
        let pw = self.password.as_deref().ok_or(Error::NeedPassword)?;
        let cached = self.keys.lock().unwrap().iter().find(|(s, l, _)| *s == p.salt && *l == p.kdf_log).map(|(_, _, k)| k.clone());
        let k = match cached {
            Some(k) => k,
            None => {
                // derived without holding the lock: other threads keep going
                let k = std::sync::Arc::new(crypto::derive(pw, &p.salt, p.kdf_log)?);
                self.keys.lock().unwrap().push((p.salt, p.kdf_log, k.clone()));
                k
            }
        };
        if p.check.is_some_and(|c| !k.matches(&c)) {
            return Err(Error::BadPassword);
        }
        Ok(k)
    }

    /// Checks the password against the first encrypted member's check value (archives with
    /// encrypted names were checked when opened). `Ok` when nothing can tell up front.
    pub fn verify_password(&self) -> Result<()> {
        if self.format == Format::SevenZ {
            // no check value: decode the smallest encrypted folder's first member
            let Some((fi, f)) = self.folders.iter().enumerate().filter(|(_, f)| f.supported() && self.entries.iter().any(|e| e.folder == Some(0) || e.encrypted)).filter(|(i, _)| self.entries.iter().any(|e| e.folder == Some(*i as u32) && e.encrypted)).min_by_key(|(_, f)| f.size()) else {
                return Ok(());
            };
            let sizes: Vec<u64> = self.entries.iter().filter(|e| e.folder == Some(fi as u32)).map(|e| e.size).collect();
            let first = self.entries.iter().find(|e| e.folder == Some(fi as u32));
            let pw = self.password_str()?;
            return sevenz::decode_folder(&self.path, f, pw, &self.sz_keys, &sevenz::Ctx::SERIAL, &sizes[..1.min(sizes.len())], |_, r| {
                let mut h = crc32fast::Hasher::new();
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    let n = r.read(&mut buf).map_err(|_| Error::BadPassword)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                if first.and_then(|e| e.crc32).is_some_and(|c| c != h.finalize()) {
                    return Err(Error::BadPassword);
                }
                Ok(())
            })
            .map_err(|e| if matches!(e, Error::Corrupt(_)) { Error::BadPassword } else { e });
        }
        if self.format == Format::Zip {
            return match self.entries.iter().find(|e| e.encrypted && !e.is_dir && zip::supported(e)) {
                Some(e) => {
                    let mut src = volume::open_concat(&self.volumes)?;
                    zip::verify(&mut *src, e, self.password.as_deref())
                }
                None => Ok(()),
            };
        }
        if self.rar4.is_some() {
            // RAR 3.x data has no password check value: decode the smallest encrypted member
            // that starts a chain (decodable on its own) and let its CRC tell
            if self.password.is_none() && self.needs_password() {
                return Err(Error::NeedPassword);
            }
            let Some(c) = self
                .chains()
                .into_iter()
                .filter(|c| self.entries[c.start].encrypted && !self.entries[c.start].is_dir && self.entries[c.start].size > 0)
                .min_by_key(|c| self.entries[c.start].size)
            else {
                return Ok(());
            };
            struct Discard;
            impl Sink for Discard {
                fn begin(&mut self, _: &Entry) -> std::io::Result<bool> {
                    Ok(true)
                }
                fn data(&mut self, _: &[u8]) -> std::io::Result<()> {
                    Ok(())
                }
                fn end(&mut self, _: &Entry) -> std::io::Result<()> {
                    Ok(())
                }
            }
            self.prepare_keys(1)?;
            let mut r = Reader::new(&self.volumes);
            return self
                .extract_chain(&mut r, c.start..c.start + 1, &mut Discard, 0)
                .map_err(|e| if matches!(e, Error::Corrupt(_) | Error::BadChecksum(_)) { Error::BadPassword } else { e });
        }
        match self.entries.iter().find_map(|e| e.crypt.as_deref()) {
            Some(p) => self.keys_for(p).map(|_| ()),
            None => Ok(()),
        }
    }

    /// Derives the keys of every encrypted member up front, on all threads (some archivers
    /// give each member its own salt, and each derivation is deliberately slow).
    fn prepare_keys(&self, threads: usize) -> Result<()> {
        if let Some(sh) = &self.rar4 {
            return sh.prepare_keys(&self.entries, threads, self.priority);
        }
        let mut todo: Vec<&crypto::Params> = Vec::new();
        for p in self.entries.iter().filter_map(|e| e.crypt.as_deref()) {
            if !todo.iter().any(|q| q.salt == p.salt && q.kdf_log == p.kdf_log) {
                todo.push(p);
            }
        }
        if todo.len() < 2 || self.password.is_none() {
            return Ok(());
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failed = std::sync::Mutex::new(None);
        std::thread::scope(|s| {
            for _ in 0..threads.clamp(1, todo.len()) {
                s.spawn(|| {
                    crate::cpu::apply_priority(self.priority);
                    while let Some(p) = todo.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
                        if let Err(e) = self.keys_for(p) {
                            failed.lock().unwrap().get_or_insert(e);
                            return;
                        }
                    }
                });
            }
        });
        match failed.into_inner().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Part of a multi-volume set.
    pub fn is_volume(&self) -> bool {
        self.volume
    }

    /// Processor priority of the threads extraction starts ([`Priority::Low`] unless set).
    /// The thread calling `extract` keeps its own priority.
    pub fn set_priority(&mut self, p: Priority) {
        self.priority = p;
    }

    /// Rough cap on the memory parallel extraction may hold for decoder windows and
    /// buffers (unless set: an eighth of the free memory, 256 MB to 2 GB). Members with big dictionaries then decode fewer at a
    /// time; one always runs, whatever it needs.
    pub fn set_memory_budget(&mut self, bytes: u64) {
        self.memory_budget = bytes;
    }

    /// Memory one group needs while decoding with `parsers` parser threads.
    fn group_memory(&self, c: &std::ops::Range<usize>, parsers: usize) -> u64 {
        if self.format == Format::Zip {
            return 1 << 20; // inflate state and buffers
        }
        if self.format == Format::SevenZ {
            let f = self.entries[c.start].folder;
            return f.and_then(|f| self.folders.get(f as usize)).map_or(1 << 20, |f| f.memory());
        }
        if self.format == Format::Rar4 {
            return rar4::group_memory(self.rar4.as_deref().expect("RAR 4 state"), &self.entries[c.clone()]);
        }
        let entries = &self.entries[c.clone()];
        let size: u64 = entries.iter().filter(|e| !e.is_dir).map(|e| e.size).sum();
        let reach = entries.iter().map(|e| e.dict_size).max().unwrap_or(0).min(size);
        // pipelined: up to 8 blocks per parser in flight, each a few hundred KB at most
        let pipe = if parsers > 1 { parsers as u64 * 8 * (256 << 10) } else { 0 };
        Unpack5::window_bytes(reach, size) + pipe
    }

    /// Extracts every member in archive order, verifying checksums.
    pub fn extract(&self, sink: &mut dyn Sink) -> Result<()> {
        self.prepare_keys(crate::cpu::threads())?;
        let mut r = Reader::new(&self.volumes);
        let parsers = crate::cpu::threads().saturating_sub(1);
        for c in self.chains() {
            self.extract_chain(&mut r, c, sink, parsers)?;
        }
        Ok(())
    }

    /// Extracts with up to `threads` workers, each feeding its own sink from `make_sink`.
    /// Members that don't depend on each other (every member of a non-solid archive,
    /// each solid group) decode in parallel; a sink sees its members in archive order.
    pub fn extract_parallel<S: Sink + Send>(&self, threads: usize, make_sink: impl Fn() -> S + Sync) -> Result<()> {
        self.prepare_keys(threads)?;
        let packed = |c: &std::ops::Range<usize>| self.entries[c.clone()].iter().map(|e| e.packed_size).sum::<u64>();
        let mut chains = self.chains();
        // biggest first, so a large member doesn't start last
        chains.sort_by_key(|c| std::cmp::Reverse(packed(c)));
        // A group that is a big share of the work would leave the other threads idle at
        // the end: it gets parser threads in proportion to its share (a solid archive,
        // one group, gets them all).
        let total = chains.iter().map(packed).sum::<u64>().max(1);
        let threads = threads.max(1);
        let format = self.format;
        let parsers_for = |c: &std::ops::Range<usize>| -> usize {
            if format == Format::Zip || format == Format::Rar4 {
                return 0;
            }
            let share = packed(c) as f64 / total as f64;
            ((share * threads as f64 * 2.0).round() as usize).min(threads)
        };
        let threads = threads.clamp(1, chains.len().max(1));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let budget = Budget { used: std::sync::Mutex::new(0), freed: std::sync::Condvar::new(), max: self.memory_budget };
        let failed = std::sync::Mutex::new(None::<Error>);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    crate::cpu::apply_priority(self.priority);
                    let work = || -> Result<()> {
                        let mut r = Reader::new(&self.volumes);
                        let mut sink = make_sink();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(c) = chains.get(i) else { return Ok(()) };
                            if failed.lock().unwrap().is_some() {
                                return Ok(());
                            }
                            let parsers = parsers_for(c);
                            let need = self.group_memory(c, parsers);
                            budget.take(need);
                            let res = self.extract_chain(&mut r, c.clone(), &mut sink, parsers);
                            r.dec.release_window_over(KEEP_WINDOW);
                            budget.give(need);
                            res?;
                        }
                    };
                    if let Err(e) = work() {
                        failed.lock().unwrap().get_or_insert(e);
                    }
                });
            }
        });
        match failed.into_inner().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Diagnostics: (member, blocks, blocks with new tables, total packed payload) for
    /// every compressed member, read from block headers only.
    #[doc(hidden)]
    pub fn block_stats(&self) -> Result<Vec<(String, usize, usize, u64)>> {
        let mut f = BufReader::new(File::open(&self.path)?);
        let mut out = Vec::new();
        for e in self.entries.iter().filter(|e| !e.is_dir && e.method != 0) {
            f.seek(std::io::SeekFrom::Start(e.data_offset))?;
            let (mut n, mut t, mut bytes, mut left) = (0, 0, 0u64, e.packed_size);
            while left >= 3 {
                let mut h = [0u8; 5];
                f.read_exact(&mut h[..2])?;
                let nb = ((h[0] >> 3) & 3) as usize + 1;
                f.read_exact(&mut h[2..2 + nb])?;
                let size = h[2..2 + nb].iter().rev().fold(0u64, |a, &v| a << 8 | v as u64);
                n += 1;
                t += (h[0] & 0x80 != 0) as usize;
                bytes += size;
                f.seek_relative(size as i64)?;
                left = left.saturating_sub(2 + nb as u64 + size);
                if h[0] & 0x40 != 0 {
                    break;
                }
            }
            out.push((e.name.clone(), n, t, bytes));
        }
        Ok(out)
    }

    /// Runs of members that must decode in order: each starts at a non-solid file (7z: one
    /// run per folder, and one per member without data).
    fn chains(&self) -> Vec<std::ops::Range<usize>> {
        if self.format == Format::SevenZ {
            let mut out: Vec<std::ops::Range<usize>> = Vec::new();
            for (i, e) in self.entries.iter().enumerate() {
                match out.last_mut() {
                    Some(r) if e.folder.is_some() && self.entries[r.start].folder == e.folder => r.end = i + 1,
                    _ => out.push(i..i + 1),
                }
            }
            return out;
        }
        let mut out = Vec::new();
        let mut start = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if i > start && !e.is_dir && !e.solid {
                out.push(start..i);
                start = i;
            }
        }
        if start < self.entries.len() {
            out.push(start..self.entries.len());
        }
        out
    }

    /// Decodes one group of dependent members. With `parsers > 1`, a big group has its
    /// blocks parsed on that many threads (see `unpack5::pipeline`).
    fn extract_chain(&self, r: &mut Reader, chain: std::ops::Range<usize>, sink: &mut dyn Sink, parsers: usize) -> Result<()> {
        let entries = &self.entries[chain];
        if self.format == Format::Zip {
            return self.extract_zip(r, entries, sink);
        }
        if self.format == Format::SevenZ {
            return self.extract_7z(entries, sink, parsers);
        }
        if let Some(sh) = &self.rar4 {
            return rar4::extract_chain(sh, entries, &mut r.files, &mut r.rar4, sink);
        }
        // a match can't reach further back than the group has produced
        let reach = entries.iter().map(|e| e.dict_size).max().unwrap_or(0).min(entries.iter().map(|e| e.size).sum());
        // keys first: a wrong password stops here, before anything is written
        let mut keys = Vec::with_capacity(entries.len());
        for e in entries {
            keys.push(match &e.crypt {
                Some(p) if !e.is_dir => Some(self.keys_for(p)?),
                _ => None,
            });
        }
        for e in entries.iter().filter(|e| !e.is_dir) {
            if e.encrypted && e.crypt.is_none() {
                return Err(Error::Unsupported("encryption method"));
            }
            if e.split_before || e.split_after {
                return Err(Error::Corrupt("a volume of the set is missing"));
            }
        }
        r.dec.set_group_size(entries.iter().filter(|e| !e.is_dir).map(|e| e.size).sum());
        let packed: u64 = entries.iter().map(|e| e.packed_size).sum();
        if parsers > 1 && packed >= pipe_min() && entries.iter().any(|e| !e.is_dir && e.method != 0) {
            let members: Vec<Member> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| Member {
                    parts: e.parts.clone(),
                    size: e.size,
                    stored: e.method == 0,
                    solid: e.solid,
                    algo: e.algo,
                    is_dir: e.is_dir,
                    crypt: e.crypt.as_ref().zip(keys[i].as_ref()).map(|(p, k)| (k.key, p.iv)),
                })
                .collect();
            let mut a = Adapt { entries, keys: &keys, sink, want: false, crc: Check::new(&entries[0]) };
            return unpack5::decode_chain(&self.volumes, &members, reach, parsers, self.priority, &mut r.dec, &mut a);
        }
        let (files, dec) = (&mut r.files, &mut r.dec);
        for (i, e) in entries.iter().enumerate() {
            let want = sink.begin(e)?;
            if e.is_dir {
                sink.end(e)?;
                continue;
            }
            let needed_later = entries[i + 1..].iter().any(|n| !n.is_dir && n.solid);
            if !want && !needed_later {
                continue;
            }
            let raw = files.reader(&e.parts);
            let mut src: Box<dyn Read + '_> = match (&e.crypt, &keys[i]) {
                (Some(p), Some(k)) => Box::new(crypto::DecryptReader::new(raw, &k.key, &p.iv)),
                _ => Box::new(raw),
            };
            let mut crc = Check::new(e);
            let mut out = |d: &[u8]| -> Result<()> {
                crc.update(d);
                if want {
                    sink.data(d)?;
                }
                Ok(())
            };
            let r = if e.method == 0 {
                unpack5::copy_stored(&mut src, e.size, &mut out)
            } else {
                dec.decode_file(&mut src, e.size, reach, e.algo, e.solid, false, &mut out)
            };
            r.map_err(|x| wrong_password(e, x))?;
            drop(src);
            check_crc(e, keys[i].as_deref(), crc)?;
            if want {
                sink.end(e)?;
            }
        }
        Ok(())
    }
}

impl Archive {
    /// The password as text (7z wants UTF-16 of it).
    fn password_str(&self) -> Result<Option<&str>> {
        match &self.password {
            None => Ok(None),
            Some(p) => std::str::from_utf8(p).map(Some).map_err(|_| Error::BadPassword),
        }
    }

    fn extract_7z(&self, entries: &[Entry], sink: &mut dyn Sink, parsers: usize) -> Result<()> {
        let Some(fi) = entries[0].folder else {
            // members without data
            for e in entries {
                if sink.begin(e)? || e.is_dir {
                    sink.end(e)?;
                }
            }
            return Ok(());
        };
        let folder = self.folders.get(fi as usize).ok_or(Error::Corrupt("7z folder"))?;
        if !folder.supported() {
            return Err(Error::Unsupported("7z coder"));
        }
        let sizes: Vec<u64> = entries.iter().map(|e| e.size).collect();
        let encrypted = entries.iter().any(|e| e.encrypted);
        let mut buf = vec![0u8; 256 << 10];
        let ctx = sevenz::Ctx { threads: parsers, priority: self.priority, budget: self.memory_budget };
        sevenz::decode_folder(&self.path, folder, self.password_str()?, &self.sz_keys, &ctx, &sizes, |i, r| {
            let e = &entries[i];
            let want = sink.begin(e)?;
            if !want {
                return Ok(());
            }
            let mut crc = crc32fast::Hasher::new();
            let mut got = 0u64;
            loop {
                let n = r.read(&mut buf).map_err(|x| sevenz::map_io(x, encrypted))?;
                if n == 0 {
                    break;
                }
                got += n as u64;
                crc.update(&buf[..n]);
                sink.data(&buf[..n])?;
            }
            if got != e.size {
                return Err(if encrypted { Error::BadPassword } else { Error::Corrupt("7z data ends early") });
            }
            if e.crc32.is_some_and(|c| c != crc.finalize()) {
                return Err(if encrypted { Error::BadPassword } else { Error::BadChecksum(e.name.clone()) });
            }
            sink.end(e)?;
            Ok(())
        })
    }

    fn extract_zip(&self, r: &mut Reader, entries: &[Entry], sink: &mut dyn Sink) -> Result<()> {
        for e in entries {
            let want = sink.begin(e)?;
            if e.is_dir {
                sink.end(e)?;
                continue;
            }
            if !want {
                continue;
            }
            if !zip::supported(e) {
                return Err(Error::Unsupported("ZIP compression or encryption method"));
            }
            let st = r.zip.get_or_insert_with(zip::State::new);
            let mut crc = crc32fast::Hasher::new();
            if r.zip_src.is_none() {
                r.zip_src = Some(volume::open_concat(&self.volumes)?);
            }
            let src = r.zip_src.as_deref_mut().unwrap();
            zip::decode(src, e, st, self.password.as_deref(), &mut |d| {
                crc.update(d);
                sink.data(d)?;
                Ok(())
            })?;
            if e.crc32.is_some_and(|c| c != crc.finalize()) {
                return Err(Error::BadChecksum(e.name.clone()));
            }
            sink.end(e)?;
        }
        Ok(())
    }
}

/// Groups with less packed data than this decode on one thread
/// (`RARCHIVE_PIPE_MIN` overrides it, for tests).
fn pipe_min() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("RARCHIVE_PIPE_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(4 << 20))
}

/// Windows up to this size stay allocated between groups (reuse beats reallocating).
const KEEP_WINDOW: usize = 8 << 20;

/// Memory accounting for parallel extraction.
struct Budget {
    used: std::sync::Mutex<u64>,
    freed: std::sync::Condvar,
    max: u64,
}

impl Budget {
    /// Waits until `need` fits (or nothing else is running), then books it.
    fn take(&self, need: u64) {
        let mut used = self.used.lock().unwrap();
        while *used > 0 && *used + need > self.max {
            used = self.freed.wait(used).unwrap();
        }
        *used += need;
    }
    fn give(&self, need: u64) {
        *self.used.lock().unwrap() -= need;
        self.freed.notify_all();
    }
}

/// Compares a member's checksum (MAC'ed with the hash key for encrypted members that hide
/// their checksums). A mismatch on an encrypted member without a password check value is
/// most likely a wrong password.
fn check_crc(e: &Entry, keys: Option<&crypto::Keys>, check: Check) -> Result<()> {
    let mac = match (&e.crypt, keys) {
        (Some(p), Some(k)) if p.mac_checksums => Some(k),
        _ => None,
    };
    let ok = match (check.b2, e.blake2sp) {
        (Some(h), Some(stored)) => {
            let d = h.finish();
            mac.map_or(d, |k| k.mac_hash(&d)) == stored
        }
        _ => match e.crc32 {
            Some(stored) => {
                let c = check.crc.finalize();
                mac.map_or(c, |k| k.mac_crc(c)) == stored
            }
            None => true,
        },
    };
    if !ok {
        return Err(wrong_password(e, Error::BadChecksum(e.name.clone())));
    }
    Ok(())
}

/// A RAR member's running checksum: CRC32, or BLAKE2sp when that's all the member has
/// (`RARCHIVE_PREFER_BLAKE2=1` uses BLAKE2sp whenever it's there, for tests).
pub(crate) struct Check {
    crc: crc32fast::Hasher,
    b2: Option<crate::blake2sp::Hasher>,
}

impl Check {
    fn new(e: &Entry) -> Check {
        static PREFER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let prefer = *PREFER.get_or_init(|| std::env::var_os("RARCHIVE_PREFER_BLAKE2").is_some_and(|v| v != "0"));
        let b2 = e.blake2sp.is_some() && (e.crc32.is_none() || prefer);
        Check { crc: crc32fast::Hasher::new(), b2: b2.then(crate::blake2sp::Hasher::new) }
    }

    pub(crate) fn update(&mut self, d: &[u8]) {
        match &mut self.b2 {
            Some(h) => h.update(d),
            None => self.crc.update(d),
        }
    }
}

/// Decoding errors on an encrypted member whose password wasn't verified up front mean a
/// wrong password far more often than damage.
fn wrong_password(e: &Entry, err: Error) -> Error {
    match (&e.crypt, &err) {
        (Some(p), Error::Corrupt(_) | Error::BadChecksum(_)) if p.check.is_none() => Error::BadPassword,
        _ => err,
    }
}

/// Reads one base header into `body` (from the type field on), checking its CRC;
/// `key` decrypts archives with encrypted headers. Returns the bytes consumed, or `None`
/// at the end of the file.
/// Opens a RAR 5 file and checks its signature.
fn open_rar5(p: &Path) -> Result<BufReader<File>> {
    let mut f = BufReader::with_capacity(64 << 10, File::open(p)?);
    let mut sig = [0u8; 8];
    f.read_exact(&mut sig)?;
    if &sig != SIG5 {
        return Err(Error::Corrupt("volume is not a RAR 5 file"));
    }
    Ok(f)
}

fn read_header(f: &mut BufReader<File>, key: Option<&crypto::Keys>, body: &mut Vec<u8>) -> Result<Option<u64>> {
    let Some(key) = key else {
        let mut crc = [0u8; 4];
        match f.read(&mut crc[..1])? {
            0 => return Ok(None), // no end-of-archive header: tolerate
            _ => f.read_exact(&mut crc[1..])?,
        }
        let (size, size_bytes) = read_vint_io(f)?;
        if size == 0 || size > MAX_HEADER {
            return Err(Error::Corrupt("header size"));
        }
        body.clear();
        body.resize(size as usize, 0);
        f.read_exact(body)?;
        let mut h = crc32fast::Hasher::new();
        h.update(&size_bytes.0[..size_bytes.1]);
        h.update(body);
        if h.finalize() != u32::from_le_bytes(crc) {
            return Err(Error::Corrupt("header checksum"));
        }
        return Ok(Some(4 + size_bytes.1 as u64 + size));
    };
    // encrypted: a 16-byte IV, then the header padded to whole AES blocks
    let mut iv = [0u8; 16];
    match f.read(&mut iv[..1])? {
        0 => return Ok(None),
        _ => f.read_exact(&mut iv[1..])?,
    }
    let mut dec = crypto::Decrypt::new(&key.key, &iv);
    let mut first = [0u8; 16];
    f.read_exact(&mut first)?;
    dec.apply(&mut first);
    let mut c = Cursor { b: &first[4..], i: 0 };
    let size = c.vint().map_err(|_| Error::BadPassword)?;
    let head = 4 + c.i;
    if size == 0 || size > MAX_HEADER || c.i > 3 {
        return Err(Error::BadPassword); // garbage: the key is wrong
    }
    let total = head + size as usize;
    let padded = total.div_ceil(16) * 16;
    let mut all = first.to_vec();
    all.resize(padded, 0);
    f.read_exact(&mut all[16..])?;
    dec.apply(&mut all[16..]);
    if crc32fast::hash(&all[4..total]) != u32::from_le_bytes(all[..4].try_into().unwrap()) {
        return Err(Error::BadPassword);
    }
    body.clear();
    body.extend_from_slice(&all[head..total]);
    Ok(Some(16 + padded as u64))
}

/// Feeds a pipeline's members to a [`Sink`], checking checksums.
struct Adapt<'a> {
    entries: &'a [Entry],
    keys: &'a [Option<std::sync::Arc<crypto::Keys>>],
    sink: &'a mut dyn Sink,
    want: bool,
    crc: Check,
}

impl MemberSink for Adapt<'_> {
    fn begin(&mut self, i: usize) -> Result<()> {
        self.want = self.sink.begin(&self.entries[i])?;
        self.crc = Check::new(&self.entries[i]);
        Ok(())
    }
    fn data(&mut self, d: &[u8]) -> Result<()> {
        self.crc.update(d);
        if self.want {
            self.sink.data(d)?;
        }
        Ok(())
    }
    fn end(&mut self, i: usize) -> Result<()> {
        let e = &self.entries[i];
        if e.is_dir {
            self.sink.end(e)?;
            return Ok(());
        }
        let crc = std::mem::replace(&mut self.crc, Check::new(e));
        check_crc(e, self.keys[i].as_deref(), crc)?;
        if self.want {
            self.sink.end(e)?;
        }
        Ok(())
    }
}

/// One worker's open archive file and decoder.
struct Reader {
    files: volume::Files,
    dec: Unpack5,
    zip: Option<zip::State>,
    /// The ZIP data, opened on first use (several files for a split set).
    zip_src: Option<Box<dyn volume::ReadSeek>>,
    rar4: Option<Box<rar4::Decoder>>,
}

impl Reader {
    fn new(volumes: &[PathBuf]) -> Reader {
        Reader { files: volume::Files::new(volumes), dec: Unpack5::new(), zip: None, zip_src: None, rar4: None }
    }
}

fn parse_file(c: &mut Cursor, extra: &[u8]) -> Result<Entry> {
    let fflags = c.vint()?;
    let size = c.vint()?;
    let attributes = c.vint()?;
    let mtime = if fflags & 2 != 0 { Some(unix_time(c.u32()? as u64, 0)) } else { None };
    let crc32 = if fflags & 4 != 0 { Some(c.u32()?) } else { None };
    let comp = c.vint()?;
    let _host_os = c.vint()?;
    let name_len = c.vint()? as usize;
    let name_bytes = c.take(name_len)?;
    let algo = (comp & 0x3f) as u8;
    let mut dict_size = 0x20000u64 << ((comp >> 10) & 0x1f).min(23);
    if algo == 1 {
        dict_size += dict_size / 32 * ((comp >> 15) & 0x1f);
    }
    let mut e = Entry {
        name: String::from_utf8_lossy(name_bytes).into_owned(),
        raw_name: name_bytes.to_vec(),
        is_dir: fflags & 1 != 0,
        size: if fflags & 8 != 0 { u64::MAX } else { size },
        packed_size: 0,
        attributes,
        mtime,
        dos_time: None,
        crc32,
        blake2sp: None,
        encrypted: false,
        is_link: false,
        method: ((comp >> 7) & 7) as u16,
        algo,
        solid: comp & 0x40 != 0,
        dict_size,
        split_before: false,
        split_after: false,
        data_offset: 0,
        crypt: None,
        parts: Vec::new(),
        zip: None,
        folder: None,
    };
    // extra area records: size, type, data
    let mut x = Cursor { b: extra, i: 0 };
    while x.i < extra.len() {
        let rsize = x.vint()? as usize;
        let start = x.i;
        let end = start.checked_add(rsize).filter(|&e| e <= extra.len()).ok_or(Error::Corrupt("extra record"))?;
        let rtype = x.vint()?;
        match rtype {
            1 => {
                e.encrypted = true;
                // version, flags, iteration log, salt, IV, [check value]
                if x.vint()? == 0 {
                    let fl = x.vint()?;
                    let kdf_log = x.take(1)?[0];
                    let salt = x.take(16)?.try_into().unwrap();
                    let iv = x.take(16)?.try_into().unwrap();
                    let check = if fl & 1 != 0 { Some(x.take(12)?.try_into().unwrap()) } else { None };
                    e.crypt = Some(Box::new(crypto::Params { kdf_log, salt, iv, check, mac_checksums: fl & 2 != 0 }));
                }
            }
            5 => e.is_link = true,
            3 => {
                // high-precision times: flags, then mtime / ctime / atime as present
                let tflags = x.vint()?;
                if tflags & 2 != 0 {
                    e.mtime = Some(if tflags & 1 != 0 {
                        let secs = x.u32()? as u64;
                        // nanoseconds follow the times when flag 0x10 is set; read them below
                        let mut nanos = 0;
                        if tflags & 0x10 != 0 {
                            let skip = 4 * ((tflags & 4 != 0) as usize + (tflags & 8 != 0) as usize);
                            let mut y = Cursor { b: x.b, i: x.i + skip };
                            nanos = y.u32()?.min(999_999_999);
                        }
                        unix_time(secs, nanos)
                    } else {
                        filetime(u64::from_le_bytes(x.take(8)?.try_into().unwrap()))
                    });
                }
            }
            2 => {
                if x.vint()? == 0 {
                    let h = x.take(32)?;
                    e.blake2sp = Some(h.try_into().unwrap());
                }
            }
            _ => {}
        }
        x.i = end;
    }
    if e.size == u64::MAX && !e.is_dir {
        return Err(Error::Unsupported("members of unknown size"));
    }
    Ok(e)
}

pub(crate) fn unix_time(secs: u64, nanos: u32) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
}

/// Windows FILETIME: 100 ns ticks since 1601.
pub(crate) fn filetime(t: u64) -> std::time::SystemTime {
    const UNIX_OFFSET: u64 = 116_444_736_000_000_000;
    if t >= UNIX_OFFSET {
        std::time::UNIX_EPOCH + std::time::Duration::from_nanos((t - UNIX_OFFSET).saturating_mul(100))
    } else {
        std::time::UNIX_EPOCH - std::time::Duration::from_nanos((UNIX_OFFSET - t).saturating_mul(100))
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn vint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for k in 0..10 {
            let byte = *self.b.get(self.i).ok_or(Error::Corrupt("truncated header"))?;
            self.i += 1;
            v |= u64::from(byte & 0x7f) << (7 * k);
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::Corrupt("bad number"))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Corrupt("truncated header"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
}

/// Reads a vint (at most 3 bytes for a header size) and returns its raw bytes too.
fn read_vint_io(r: &mut dyn Read) -> Result<(u64, ([u8; 3], usize))> {
    let mut raw = [0u8; 3];
    let mut v = 0u64;
    for k in 0..3 {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        raw[k] = b[0];
        v |= u64::from(b[0] & 0x7f) << (7 * k);
        if b[0] & 0x80 == 0 {
            return Ok((v, (raw, k + 1)));
        }
    }
    Err(Error::Corrupt("header size"))
}

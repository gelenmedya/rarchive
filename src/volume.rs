//! Multi-volume RAR sets: volume names, and reading a member whose packed data is spread
//! over several volume files as one stream.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A piece of a member's packed data in one volume.
#[derive(Clone, Debug)]
pub(crate) struct Part {
    pub vol: u32,
    pub offset: u64,
    pub size: u64,
}

/// How the volumes of a set are named.
pub(crate) enum Naming {
    /// `name.part1.rar`, `name.part2.rar`, … (digits zero-padded to `width`).
    Parts { prefix: String, width: usize, ext: String },
    /// `name.rar`, `name.r00`, `name.r01`, …
    Old { base: String, ext: String },
}

impl Naming {
    /// The naming of the set `given` belongs to, and which volume (0-based) it is.
    pub(crate) fn of(given: &Path) -> Option<(Naming, PathBuf, usize)> {
        let dir = given.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = given.file_name()?.to_str()?;
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".rar") {
            let stem = &name[..name.len() - 4];
            let ext = name[name.len() - 4..].to_string();
            let lstem = stem.to_ascii_lowercase();
            if let Some(i) = lstem.rfind(".part") {
                let digits = &stem[i + 5..];
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    let n: usize = digits.parse().ok()?;
                    let naming = Naming::Parts { prefix: stem[..i + 5].to_string(), width: digits.len(), ext };
                    return Some((naming, dir, n.checked_sub(1)?));
                }
            }
            return Some((Naming::Old { base: stem.to_string(), ext }, dir, 0));
        }
        // name.r00 .. name.r99
        let (base, ext) = name.rsplit_once('.')?;
        let d = ext.strip_prefix(['r', 'R'])?;
        if d.len() == 2 && d.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = d.parse().ok()?;
            let rar = if ext.starts_with('R') { ".RAR" } else { ".rar" };
            return Some((Naming::Old { base: base.to_string(), ext: rar.to_string() }, dir, n + 1));
        }
        None
    }

    /// File name of volume `k` (0-based).
    pub(crate) fn name(&self, k: usize) -> String {
        match self {
            Naming::Parts { prefix, width, ext } => format!("{prefix}{:0width$}{ext}", k + 1),
            Naming::Old { base, ext } if k == 0 => format!("{base}{ext}"),
            Naming::Old { base, ext } => {
                let r = if ext.starts_with(".R") { 'R' } else { 'r' };
                format!("{base}.{r}{:02}", k - 1)
            }
        }
    }
}

/// One worker's open volume files (opened when first needed).
pub(crate) struct Files {
    paths: Vec<PathBuf>,
    /// Open file and its position (`u64::MAX` = unknown).
    open: Vec<Option<(BufReader<File>, u64)>>,
}

impl Files {
    pub(crate) fn new(paths: &[PathBuf]) -> Files {
        Files { paths: paths.to_vec(), open: (0..paths.len()).map(|_| None).collect() }
    }

    fn get(&mut self, vol: u32) -> io::Result<&mut (BufReader<File>, u64)> {
        let i = vol as usize;
        let slot = self.open.get_mut(i).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing volume"))?;
        if slot.is_none() {
            *slot = Some((BufReader::with_capacity(1 << 20, File::open(&self.paths[i])?), 0));
        }
        Ok(slot.as_mut().unwrap())
    }

    /// Reads `parts` back to back.
    pub(crate) fn reader<'a>(&'a mut self, parts: &'a [Part]) -> PartsRead<'a> {
        PartsRead { files: self, parts, next: 0, left: 0, vol: 0 }
    }
}

pub(crate) struct PartsRead<'a> {
    files: &'a mut Files,
    parts: &'a [Part],
    next: usize,
    left: u64,
    vol: u32,
}

impl Read for PartsRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            let Some(p) = self.parts.get(self.next) else { return Ok(0) };
            self.next += 1;
            let (f, pos) = self.files.get(p.vol)?;
            if *pos != p.offset {
                if *pos == u64::MAX {
                    f.seek(SeekFrom::Start(p.offset))?;
                } else {
                    f.seek_relative(p.offset as i64 - *pos as i64)?;
                }
                *pos = p.offset;
            }
            self.left = p.size;
            self.vol = p.vol;
        }
        let (f, pos) = self.files.get(self.vol)?;
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        *pos += n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Something to read archive data from: a file, or a set of files read as one.
pub(crate) trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Opens `paths` as one continuous file (a single path: just that file, buffered).
pub(crate) fn open_concat(paths: &[PathBuf]) -> io::Result<Box<dyn ReadSeek>> {
    if paths.len() == 1 {
        return Ok(Box::new(SeekBuf::new(File::open(&paths[0])?, 256 << 10)));
    }
    let mut parts = Vec::with_capacity(paths.len());
    let mut start = 0u64;
    for p in paths {
        let len = std::fs::metadata(p)?.len();
        parts.push((p.clone(), start, len));
        start += len;
    }
    Ok(Box::new(SeekBuf::new(Concat { parts, total: start, pos: 0, cur: None }, 256 << 10)))
}

/// A buffered reader whose seeks keep the buffer when the target is inside it. `BufReader`
/// drops its buffer on every seek: for a ZIP of many small members (seek to a local header,
/// skip it, read the data) that refilled 1 MB twice per member, ~2 MB copied for a 4 KB file.
pub(crate) struct SeekBuf<R> {
    inner: R,
    buf: Vec<u8>,
    /// Valid bytes in `buf`, and the read position inside them.
    filled: usize,
    at: usize,
    /// File offset of `buf[0]`.
    base: u64,
}

impl<R: Read + Seek> SeekBuf<R> {
    pub(crate) fn new(inner: R, capacity: usize) -> Self {
        SeekBuf { inner, buf: vec![0; capacity.max(4096)], filled: 0, at: 0, base: 0 }
    }
}

impl<R: Read + Seek> Read for SeekBuf<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.filled {
            // big reads skip the buffer
            if out.len() >= self.buf.len() {
                let pos = self.base + self.filled as u64;
                let n = self.inner.read(out)?;
                self.base = pos + n as u64;
                self.filled = 0;
                self.at = 0;
                return Ok(n);
            }
            self.base += self.filled as u64;
            self.filled = self.inner.read(&mut self.buf)?;
            self.at = 0;
        }
        let n = out.len().min(self.filled - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SeekBuf<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let cur = self.base + self.at as u64;
        let target = match to {
            SeekFrom::Start(x) => Some(x),
            SeekFrom::Current(d) => cur.checked_add_signed(d),
            SeekFrom::End(_) => None,
        };
        if let Some(t) = target {
            if t >= self.base && t <= self.base + self.filled as u64 {
                self.at = (t - self.base) as usize;
                return Ok(t);
            }
        }
        // outside the buffer (or from the end): a real seek
        let pos = match to {
            SeekFrom::Current(d) => self.inner.seek(SeekFrom::Start(cur.checked_add_signed(d).ok_or(io::ErrorKind::InvalidInput)?))?,
            other => self.inner.seek(other)?,
        };
        self.base = pos;
        self.filled = 0;
        self.at = 0;
        Ok(pos)
    }
}

/// Several files read as one: split archives.
struct Concat {
    /// (file, start in the whole, length)
    parts: Vec<(PathBuf, u64, u64)>,
    total: u64,
    pos: u64,
    /// The open part: index, reader, and the reader's position in that part.
    cur: Option<(usize, BufReader<File>, u64)>,
}

impl Read for Concat {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || buf.is_empty() {
            return Ok(0);
        }
        // the part holding `pos` (parts are few: a linear search is fine)
        let i = self.parts.iter().rposition(|&(_, s, _)| s <= self.pos).unwrap_or(0);
        let (ref path, start, len) = self.parts[i];
        let at = self.pos - start;
        if at >= len {
            // an empty part
            self.pos = start + len;
            return if i + 1 < self.parts.len() { self.read(buf) } else { Ok(0) };
        }
        if self.cur.as_ref().is_none_or(|c| c.0 != i) {
            self.cur = Some((i, BufReader::with_capacity(1 << 20, File::open(path)?), 0));
        }
        let (_, f, fpos) = self.cur.as_mut().unwrap();
        if *fpos != at {
            f.seek_relative(at as i64 - *fpos as i64)?;
            *fpos = at;
        }
        let want = buf.len().min((len - at).min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        *fpos += n as u64;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Concat {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.total as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

/// Numbered split parts `name.001`, `name.002`, … starting from part 1, as long as they
/// exist; `None` unless `given` is such a part.
pub(crate) fn numbered_parts(given: &Path) -> Option<Vec<PathBuf>> {
    let name = given.file_name()?.to_str()?;
    let (base, digits) = name.rsplit_once('.')?;
    if digits.len() < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let dir = given.parent().map(Path::to_path_buf).unwrap_or_default();
    let width = digits.len();
    let mut out = Vec::new();
    for k in 1.. {
        let p = dir.join(format!("{base}.{k:0width$}"));
        if !p.exists() {
            break;
        }
        out.push(p);
    }
    (!out.is_empty()).then_some(out)
}

/// The disks of a spanned ZIP set whose last disk is `last` (`x.zip`): `x.z01`, `x.z02`, …
/// then `x.zip`, for `disks` disks in all.
pub(crate) fn spanned_parts(last: &Path, disks: u32) -> Option<Vec<PathBuf>> {
    let name = last.file_name()?.to_str()?;
    let (base, ext) = name.rsplit_once('.')?;
    let z = if ext.starts_with('Z') { 'Z' } else { 'z' };
    let dir = last.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut out: Vec<PathBuf> = (1..disks).map(|k| dir.join(format!("{base}.{z}{k:02}"))).collect();
    out.push(last.to_path_buf());
    out.iter().all(|p| p.exists()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_names() {
        let (n, _, k) = Naming::of(Path::new("x/Film.part03.rar")).unwrap();
        assert_eq!((n.name(0), n.name(9), k), ("Film.part01.rar".to_string(), "Film.part10.rar".to_string(), 2));
        let (n, _, k) = Naming::of(Path::new("a.r01")).unwrap();
        assert_eq!((n.name(0), n.name(1), n.name(3), k), ("a.rar".into(), "a.r00".into(), "a.r02".into(), 2));
        let (n, _, k) = Naming::of(Path::new("tek.rar")).unwrap();
        assert_eq!((n.name(0), n.name(1), k), ("tek.rar".into(), "tek.r00".into(), 0));
        assert!(Naming::of(Path::new("a.zip")).is_none());
    }

    #[test]
    fn concat_reads_and_seeks_across_files() {
        let dir = std::env::temp_dir().join(format!("rarchive-concat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths: Vec<PathBuf> = ["a", "b", "c"].iter().map(|n| dir.join(n)).collect();
        std::fs::write(&paths[0], b"01234").unwrap();
        std::fs::write(&paths[1], b"").unwrap();
        std::fs::write(&paths[2], b"56789").unwrap();
        let mut c = open_concat(&paths).unwrap();
        let mut all = Vec::new();
        c.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"0123456789");
        c.seek(SeekFrom::Start(3)).unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"3456");
        assert_eq!(c.seek(SeekFrom::End(-2)).unwrap(), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod seekbuf_tests {
    use super::SeekBuf;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    /// Random seeks and reads give the same bytes as a plain cursor.
    #[test]
    fn matches_a_cursor() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
        let mut a = SeekBuf::new(Cursor::new(data.clone()), 4096);
        let mut b = Cursor::new(data.clone());
        let mut x = 12345u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            match rnd() % 5 {
                0 => {
                    let t = rnd() % (data.len() as u64 + 10);
                    assert_eq!(a.seek(SeekFrom::Start(t)).unwrap(), b.seek(SeekFrom::Start(t)).unwrap());
                }
                1 => {
                    let d = (rnd() % 9000) as i64 - 4500;
                    let (ra, rb) = (a.seek(SeekFrom::Current(d)), b.seek(SeekFrom::Current(d)));
                    assert_eq!(ra.is_ok(), rb.is_ok());
                    if let (Ok(pa), Ok(pb)) = (ra, rb) {
                        assert_eq!(pa, pb);
                    } else {
                        let p = b.stream_position().unwrap();
                        a.seek(SeekFrom::Start(p)).unwrap();
                    }
                }
                _ => {
                    let n = (rnd() % 20_000) as usize;
                    let (mut ba, mut bb) = (vec![0u8; n], vec![0u8; n]);
                    let ka = a.read(&mut ba).unwrap();
                    let kb = b.read(&mut bb).unwrap();
                    // a buffered reader may return fewer bytes: compare what both returned
                    let k = ka.min(kb);
                    assert_eq!(ba[..k], bb[..k]);
                    if ka != kb {
                        let p = a.stream_position().unwrap();
                        b.seek(SeekFrom::Start(p)).unwrap();
                    }
                }
            }
            assert_eq!(a.stream_position().unwrap(), b.stream_position().unwrap());
        }
    }
}

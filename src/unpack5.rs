//! RAR 5 LZ decoder.
//!
//! Layout: a ring window (the dictionary plus room for not-yet-flushed output, so the
//! bytes a match may refer to are never the ones being written) followed by [`SLACK`] bytes. The
//! hot loop writes linearly from index `wp < W`; a match may run into the slack area,
//! which is folded back to the start of the ring when `wp` passes `W`. Matches copy in
//! 16-byte chunks and may scribble up to 16 bytes past their end: those positions are
//! either future output or older than any legal distance.
//!
//! Decoded bytes leave the window through [`Unpack5::flush`], which runs the filters on a
//! copy (later matches must see the unfiltered bytes).

use std::collections::VecDeque;
use std::io::Read;

use crate::bits::{Bits, PAD};
use crate::error::{Error, Result};
use crate::filter::{self, Filter, Kind};
use crate::huffman::Huffman;

mod pipeline;
pub(crate) use pipeline::{Member, MemberSink, decode_chain};

const MAIN_SIZE: usize = 306;
const DIST_SIZE_V0: usize = 64;
const DIST_SIZE_V1: usize = 80;
const ALIGN_SIZE: usize = 16;
const LEN_SIZE: usize = 44;
/// Longest match: length slot 43 with all extra bits, plus the distance bonus.
const MAX_MATCH: usize = 4100;
const SLACK: usize = MAX_MATCH + 64 + 4096;
/// Output is handed to the sink about this often.
const CHUNK: u64 = 256 << 10;
const MAX_FILTERS: usize = 8192;

pub(crate) struct Tables {
    main: Huffman,
    dist: Huffman,
    align: Huffman,
    len: Huffman,
    align_mode: bool,
    dist_count: u32,
}

pub(crate) struct Unpack5 {
    win: Vec<u8>,
    /// Ring size W; `win.len() == W + SLACK`.
    w: usize,
    /// Absolute position of `win[0]` in the current lap.
    lap: u64,
    /// Write index, `< w` between hot-loop runs.
    wp: usize,
    flushed: u64,
    reps: [usize; 4],
    last_len: usize,
    tables: Option<Box<Tables>>,
    filters: VecDeque<Filter>,
    payload: Vec<u8>,
    fbuf: Vec<u8>,
    fscratch: Vec<u8>,
    /// Current file: absolute start and end, and where the next housekeeping stop is.
    file_start: u64,
    file_end: u64,
    next_stop: u64,
    /// Total output of the group being decoded (bounds filter blocks).
    group_size: u64,
}

pub(crate) struct Block {
    pub(crate) last: bool,
    pub(crate) tables: bool,
    pub(crate) bits: usize,
}

impl Unpack5 {
    pub(crate) fn new() -> Self {
        Unpack5 {
            win: Vec::new(),
            w: 0,
            lap: 0,
            wp: 0,
            flushed: 0,
            reps: [0; 4],
            last_len: 0,
            tables: None,
            filters: VecDeque::new(),
            payload: Vec::new(),
            fbuf: Vec::new(),
            fscratch: Vec::new(),
            file_start: 0,
            file_end: 0,
            next_stop: 0,
            group_size: u64::MAX,
        }
    }

    /// Bytes the window takes for a group with history `reach` and output `group_size`.
    pub(crate) fn window_bytes(reach: u64, group_size: u64) -> u64 {
        reach + CHUNK + (filter::MAX_LEN as u64).min(group_size) + (64 << 10) + SLACK as u64
    }

    /// Frees the window if it is bigger than `limit` bytes (a worker going on to small
    /// members shouldn't keep a big dictionary's memory).
    pub(crate) fn release_window_over(&mut self, limit: usize) {
        if self.win.len() > limit {
            self.win = Vec::new();
            self.w = 0;
            self.lap = self.pos();
            self.wp = 0;
        }
    }

    /// Tells the decoder how much output the coming group of members has in total.
    pub(crate) fn set_group_size(&mut self, size: u64) {
        self.group_size = size;
    }

    #[inline(always)]
    fn pos(&self) -> u64 {
        self.lap + self.wp as u64
    }

    /// Index in `win` of absolute position `a`, which must lie within the last `w` bytes.
    #[inline(always)]
    fn idx(&self, a: u64) -> usize {
        if a >= self.lap { (a - self.lap) as usize } else { (a + self.w as u64 - self.lap) as usize }
    }

    /// Makes room for `reach` bytes of history (the dictionary, capped by how much the
    /// stream can produce). `solid` keeps the history; otherwise the ring restarts.
    fn ensure_window(&mut self, reach: u64, solid: bool) -> Result<()> {
        if reach > 1 << 32 {
            return Err(Error::Unsupported("dictionary larger than 4 GB"));
        }
        // Room for the history, plus everything that may be decoded but not yet flushed
        // (a chunk, a filter block, a match) without overwriting either. A filter can't
        // cover more than the group's output, so small groups get small windows.
        let filter_room = (filter::MAX_LEN as u64).min(self.group_size) as usize;
        let want = reach as usize + CHUNK as usize + filter_room + (64 << 10);
        let pos = self.pos();
        if want <= self.w {
            if !solid {
                self.lap = pos;
                self.wp = 0;
            }
            return Ok(());
        }
        let mut win = vec![0u8; want + SLACK];
        let mut keep = 0usize;
        if solid && self.w != 0 {
            // carry the history over into the bigger ring
            keep = self.w.min(pos as usize);
            for (k, a) in (pos - keep as u64..pos).enumerate() {
                win[k] = self.win[self.idx(a)];
            }
        }
        self.win = win;
        self.w = want;
        self.lap = pos - keep as u64;
        self.wp = keep;
        Ok(())
    }

    /// Decodes one file of `size` bytes from `src` (its packed data), passing the output
    /// to `out`. `solid` continues the previous file's state.
    pub(crate) fn decode_file(
        &mut self,
        src: &mut dyn Read,
        size: u64,
        reach: u64,
        algo: u8,
        solid: bool,
        file_crc_skip: bool,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let _ = file_crc_skip;
        self.begin_file(size, reach, algo, solid)?;
        let (file_start, file_end) = (self.file_start, self.file_end);
        let mut payload = std::mem::take(&mut self.payload);
        let mut tables = self.tables.take();
        let result = (|| -> Result<()> {
            while self.pos() < file_end {
                let Some(block) = read_block(src, &mut payload)? else {
                    return Err(Error::Corrupt("compressed data ends early"));
                };
                let mut b = Bits::new(&payload);
                if block.tables {
                    tables = Some(Box::new(read_tables(&mut b, block.bits, algo)?));
                }
                let t = tables.as_deref().ok_or(Error::Corrupt("block without Huffman tables"))?;
                loop {
                    let stop = file_end.min(self.pos() + CHUNK);
                    let stop_wp = ((stop - self.lap) as usize).min(self.w);
                    self.run(&mut b, t, block.bits, stop_wp, file_start)?;
                    if self.wp >= self.w {
                        self.wrap();
                    }
                    let upto = self.pos().min(file_end);
                    self.flush(upto, file_start, out)?;
                    if b.pos() >= block.bits || self.pos() >= file_end {
                        break;
                    }
                }
                if block.last {
                    break;
                }
            }
            self.finish_file(out)
        })();
        self.payload = payload;
        self.tables = tables;
        result
    }

    /// Starts a file of `size` bytes: resets the state unless `solid` continues it.
    fn begin_file(&mut self, size: u64, reach: u64, algo: u8, solid: bool) -> Result<()> {
        if algo > 1 {
            return Err(Error::Unsupported("unknown RAR 5 compression version"));
        }
        if !solid {
            self.reps = [0; 4];
            self.last_len = 0;
            self.tables = None;
        }
        self.ensure_window(reach, solid)?;
        self.filters.clear();
        self.file_start = self.pos();
        self.flushed = self.file_start;
        self.file_end = self.file_start + size;
        self.next_stop = self.file_end.min(self.file_start + CHUNK);
        Ok(())
    }

    /// Ends the current file: checks it is complete and flushes the rest.
    fn finish_file(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let file_end = self.file_end;
        if self.pos() < file_end {
            return Err(Error::Corrupt("compressed data ends early"));
        }
        if self.pos() > file_end {
            // a damaged stream wrote past the file: drop the excess
            if file_end < self.lap {
                self.lap -= self.w as u64;
            }
            self.wp = (file_end - self.lap) as usize;
        }
        // filters reaching past the file are damaged: drop them, keep the bytes
        self.filters.retain(|f| f.start + f.len as u64 <= file_end);
        self.flush(file_end, self.file_start, out)
    }

    /// Moves bytes written past the ring end back to its start.
    fn wrap(&mut self) {
        let over = self.wp - self.w;
        self.win.copy_within(self.w..self.w + over, 0);
        self.wp = over;
        self.lap += self.w as u64;
    }

    /// The hot loop: decodes symbols until the block's bits run out or `wp` reaches `stop_wp`.
    /// Picks the hot loop compiled for this CPU: x86-64 builds carry a second copy using
    /// BMI2 (single-instruction variable shifts) and pick it at run time, so the same
    /// binary runs everywhere and takes what newer processors offer.
    fn run(&mut self, b: &mut Bits, t: &Tables, end_bit: usize, stop_wp: usize, file_start: u64) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        if crate::cpu::bmi2() {
            // SAFETY: the CPU supports the features run_bmi2 was compiled for
            return unsafe { self.run_bmi2(b, t, end_bit, stop_wp, file_start) };
        }
        self.run_generic(b, t, end_bit, stop_wp, file_start)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi1,bmi2,lzcnt,popcnt")]
    unsafe fn run_bmi2(&mut self, b: &mut Bits, t: &Tables, end_bit: usize, stop_wp: usize, file_start: u64) -> Result<()> {
        self.run_impl(b, t, end_bit, stop_wp, file_start)
    }

    #[inline(never)]
    fn run_generic(&mut self, b: &mut Bits, t: &Tables, end_bit: usize, stop_wp: usize, file_start: u64) -> Result<()> {
        self.run_impl(b, t, end_bit, stop_wp, file_start)
    }

    #[inline(always)]
    fn run_impl(&mut self, b: &mut Bits, t: &Tables, end_bit: usize, stop_wp: usize, file_start: u64) -> Result<()> {
        let mut wp = self.wp;
        let mut reps = self.reps;
        let mut last_len = self.last_len;
        debug_assert!(self.win.len() >= self.w + SLACK);
        let win = self.win.as_mut_ptr();
        let w = self.w;
        let res = loop {
            if wp >= stop_wp || b.pos() >= end_bit {
                break Ok(());
            }
            b.refill();
            let sym = t.main.decode(b);
            if sym < 256 {
                // SAFETY: wp < stop_wp <= w <= win.len()
                unsafe { *win.add(wp) = sym as u8 };
                wp += 1;
                continue;
            }
            if sym >= 262 {
                if sym as usize >= MAIN_SIZE {
                    break Err(Error::Corrupt("invalid code"));
                }
                let slot = (sym - 262) as usize;
                let mut len = LEN_BASE[slot] as usize + b.read(LEN_BITS[slot] as u32) as usize;
                let ds = t.dist.decode(b);
                if ds >= t.dist_count {
                    break Err(Error::Corrupt("invalid distance code"));
                }
                b.refill();
                let dist = if ds < 4 {
                    ds as usize + 1
                } else {
                    let nb = (ds - 2) >> 1;
                    let base = ((2 | (ds as usize & 1)) << nb) + 1;
                    if nb >= 4 && t.align_mode {
                        let hi = if nb > 4 { b.read(nb - 4) as usize } else { 0 };
                        let lo = t.align.decode(b);
                        if lo >= 16 {
                            break Err(Error::Corrupt("invalid align code"));
                        }
                        base + (hi << 4 | lo as usize)
                    } else if nb > 32 {
                        // RAR 7 distances need more than one read
                        let hi = b.read(nb - 32) as usize;
                        b.refill();
                        base + (hi << 32 | b.read(32) as usize)
                    } else {
                        base + b.read(nb) as usize
                    }
                };
                len += (dist > 0x100) as usize + (dist > 0x2000) as usize + (dist > 0x40000) as usize;
                reps = [dist, reps[0], reps[1], reps[2]];
                last_len = len;
                // SAFETY: see copy_match
                unsafe { copy_match(win, wp, dist, len, w) };
                wp += len;
                continue;
            }
            match sym {
                256 => {
                    self.wp = wp;
                    if let Err(e) = self.read_filter(b, file_start) {
                        break Err(e);
                    }
                }
                257 => {
                    if last_len != 0 {
                        unsafe { copy_match(win, wp, reps[0], last_len, w) };
                        wp += last_len;
                    }
                }
                _ => {
                    let i = (sym - 258) as usize;
                    let dist = reps[i];
                    if dist == 0 {
                        break Err(Error::Corrupt("repeat distance before any match"));
                    }
                    let ls = t.len.decode(b);
                    if ls as usize >= LEN_SIZE {
                        break Err(Error::Corrupt("invalid length code"));
                    }
                    let len = LEN_BASE[ls as usize] as usize + b.read(LEN_BITS[ls as usize] as u32) as usize;
                    let mut k = i;
                    while k > 0 {
                        reps[k] = reps[k - 1];
                        k -= 1;
                    }
                    reps[0] = dist;
                    last_len = len;
                    unsafe { copy_match(win, wp, dist, len, w) };
                    wp += len;
                }
            }
        };
        self.wp = wp;
        self.reps = reps;
        self.last_len = last_len;
        res
    }

    fn read_filter(&mut self, b: &mut Bits, file_start: u64) -> Result<()> {
        fn number(b: &mut Bits) -> u32 {
            let n = b.read_slow(2) + 1;
            let mut v = 0u32;
            for i in 0..n {
                v |= b.read_slow(8) << (i * 8);
            }
            v
        }
        let offset = number(b);
        let len = number(b);
        let kind = match b.read_slow(3) {
            0 => Kind::Delta { channels: b.read_slow(5) + 1 },
            1 => Kind::E8,
            2 => Kind::E8E9,
            3 => Kind::Arm,
            _ => return Err(Error::Corrupt("unknown filter")),
        };
        if len > filter::MAX_LEN {
            return Err(Error::Corrupt("filter block too large"));
        }
        if self.filters.len() >= MAX_FILTERS {
            return Err(Error::Corrupt("too many filters"));
        }
        let _ = file_start;
        self.filters.push_back(Filter { start: self.pos() + offset as u64, len, kind });
        Ok(())
    }

    /// Hands decoded bytes up to `upto` to `out`, running filters whose block is complete.
    fn flush(&mut self, upto: u64, file_start: u64, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        while self.flushed < upto {
            if let Some(&f) = self.filters.front() {
                if f.len == 0 || f.start < self.flushed {
                    // empty, or overlaps output already written
                    self.filters.pop_front();
                    continue;
                }
                if f.start < upto {
                    if self.flushed < f.start {
                        self.emit(self.flushed, f.start, out)?;
                        self.flushed = f.start;
                    }
                    let end = f.start + f.len as u64;
                    if end > upto {
                        return Ok(()); // block not decoded yet
                    }
                    let mut data = std::mem::take(&mut self.fbuf);
                    data.clear();
                    self.collect(f.start, end, &mut data);
                    {
                        let _t = pipeline::prof::Timer::new(&pipeline::prof::FILTER);
                        filter::apply(f.kind, &mut data, f.start - file_start, &mut self.fscratch);
                    }
                    let r = {
                        let _t = pipeline::prof::Timer::new(&pipeline::prof::SINK);
                        out(&data)
                    };
                    self.fbuf = data;
                    r?;
                    self.flushed = end;
                    self.filters.pop_front();
                    continue;
                }
            }
            self.emit(self.flushed, upto, out)?;
            self.flushed = upto;
        }
        Ok(())
    }

    fn emit(&self, from: u64, to: u64, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let _t = pipeline::prof::Timer::new(&pipeline::prof::SINK);
        let a = self.idx(from);
        let n = (to - from) as usize;
        if a + n <= self.w {
            out(&self.win[a..a + n])
        } else {
            out(&self.win[a..self.w])?;
            out(&self.win[..n - (self.w - a)])
        }
    }

    fn collect(&self, from: u64, to: u64, data: &mut Vec<u8>) {
        let a = self.idx(from);
        let n = (to - from) as usize;
        if a + n <= self.w {
            data.extend_from_slice(&self.win[a..a + n]);
        } else {
            data.extend_from_slice(&self.win[a..self.w]);
            data.extend_from_slice(&self.win[..n - (self.w - a)]);
        }
    }
}

/// Copies `len` bytes from `dist` back. Callers guarantee `wp < w` and `len <= MAX_MATCH`,
/// and `win` points at `w + SLACK` bytes, so every write stays in bounds (chunked copies
/// may write up to 16 bytes past `wp + len`). Sources before the ring start wrap to its end.
#[inline(always)]
unsafe fn copy_match(win: *mut u8, wp: usize, dist: usize, len: usize, w: usize) {
    debug_assert!(wp < w && len <= MAX_MATCH);
    unsafe {
        let dst = win.add(wp);
        let (s, gap) = if dist <= wp {
            // Source in the current lap: always copy linearly, even when the match runs
            // past the ring end, because then its own fresh bytes sit in the slack area
            // (not yet folded back to the ring start).
            (wp - dist, dist)
        } else {
            // Source in the previous lap, ahead of `wp` in the buffer: no overlap.
            // (a distance beyond the ring is damaged data: any in-bounds byte will do)
            let d = if dist > w { dist % w } else { dist };
            let s = wp + w - d;
            if s + len > w {
                // it continues at the ring start, which holds this lap's bytes
                let mut t = s;
                for i in 0..len {
                    if t >= w {
                        t -= w;
                    }
                    *dst.add(i) = *win.add(t);
                    t += 1;
                }
                return;
            }
            (s, usize::MAX)
        };
        let src = win.add(s);
        if gap >= 16 {
            let mut i = 0;
            while i < len {
                let v = std::ptr::read_unaligned(src.add(i) as *const [u8; 16]);
                std::ptr::write_unaligned(dst.add(i) as *mut [u8; 16], v);
                i += 16;
            }
        } else if gap >= 8 {
            let mut i = 0;
            while i < len {
                let v = std::ptr::read_unaligned(src.add(i) as *const u64);
                std::ptr::write_unaligned(dst.add(i) as *mut u64, v);
                i += 8;
            }
        } else if gap == 1 {
            std::ptr::write_bytes(dst, *src, len);
        } else {
            for i in 0..len {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

pub(crate) fn read_block(src: &mut dyn Read, payload: &mut Vec<u8>) -> Result<Option<Block>> {
    let mut head = [0u8; 2];
    match src.read(&mut head[..1])? {
        0 => return Ok(None),
        _ => src.read_exact(&mut head[1..])?,
    }
    let (flags, check) = (head[0], head[1]);
    let size_bytes = ((flags >> 3) & 3) as usize + 1;
    if size_bytes == 4 {
        return Err(Error::Corrupt("bad block header"));
    }
    let mut sz = [0u8; 3];
    src.read_exact(&mut sz[..size_bytes])?;
    let x = sz[..size_bytes].iter().fold(flags ^ check, |a, &v| a ^ v);
    if x != 0x5a {
        return Err(Error::Corrupt("block header checksum"));
    }
    let size = sz[..size_bytes].iter().rev().fold(0usize, |a, &v| a << 8 | v as usize);
    payload.clear();
    payload.resize(size + PAD, 0);
    src.read_exact(&mut payload[..size])?;
    let bits = if size == 0 { 0 } else { (size - 1) * 8 + ((flags & 7) as usize + 1) };
    Ok(Some(Block { last: flags & 0x40 != 0, tables: flags & 0x80 != 0, bits }))
}

pub(crate) fn read_tables(b: &mut Bits, end_bit: usize, algo: u8) -> Result<Tables> {
    // level table: 20 four-bit lengths, 15 escapes a run of zeros
    let mut level = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        let l = b.read_slow(4) as u8;
        if l == 15 {
            let n = b.read_slow(4) as usize;
            if n == 0 {
                level[i] = 15;
                i += 1;
            } else {
                for _ in 0..n + 2 {
                    if i < 20 {
                        level[i] = 0;
                        i += 1;
                    }
                }
            }
        } else {
            level[i] = l;
            i += 1;
        }
    }
    let lh = Huffman::new(&level)?;
    let dist_size = if algo == 0 { DIST_SIZE_V0 } else { DIST_SIZE_V1 };
    let total = MAIN_SIZE + dist_size + ALIGN_SIZE + LEN_SIZE;
    let mut lens = vec![0u8; total];
    let mut i = 0;
    while i < total {
        if b.pos() > end_bit {
            return Err(Error::Corrupt("Huffman tables run past the block"));
        }
        b.refill();
        let n = lh.decode(b);
        match n {
            0..=15 => {
                lens[i] = n as u8;
                i += 1;
            }
            16 | 17 => {
                if i == 0 {
                    return Err(Error::Corrupt("table repeats nothing"));
                }
                let count = if n == 16 { 3 + b.read(3) } else { 11 + b.read(7) } as usize;
                let prev = lens[i - 1];
                let end = (i + count).min(total);
                lens[i..end].fill(prev);
                i = end;
            }
            18 | 19 => {
                let count = if n == 18 { 3 + b.read(3) } else { 11 + b.read(7) } as usize;
                i = (i + count).min(total);
            }
            _ => return Err(Error::Corrupt("invalid table code")),
        }
    }
    if b.pos() > end_bit {
        return Err(Error::Corrupt("Huffman tables run past the block"));
    }
    let (main, rest) = lens.split_at(MAIN_SIZE);
    let (dist, rest) = rest.split_at(dist_size);
    let (align, len) = rest.split_at(ALIGN_SIZE);
    Ok(Tables {
        main: Huffman::new(main)?,
        dist: Huffman::new(dist)?,
        align: Huffman::new(align)?,
        len: Huffman::new(len)?,
        align_mode: align.iter().any(|&l| l != 0 && l != 4),
        dist_count: dist_size as u32,
    })
}

/// Length slot → base length and extra-bit count.
const LEN_BASE: [u32; LEN_SIZE] = {
    let mut t = [0u32; LEN_SIZE];
    let mut s = 0;
    while s < LEN_SIZE {
        t[s] = if s < 8 { s as u32 + 2 } else { ((4 | (s as u32 & 3)) << ((s >> 2) - 1)) + 2 };
        s += 1;
    }
    t
};
const LEN_BITS: [u8; LEN_SIZE] = {
    let mut t = [0u8; LEN_SIZE];
    let mut s = 0;
    while s < LEN_SIZE {
        t[s] = if s < 8 { 0 } else { ((s >> 2) - 1) as u8 };
        s += 1;
    }
    t
};

/// Stored data in a solid stream doesn't touch the window; used for method 0.
pub(crate) fn copy_stored(src: &mut dyn Read, size: u64, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut buf = vec![0u8; (size.min(1 << 20)) as usize];
    let mut left = size;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        src.read_exact(&mut buf[..n])?;
        out(&buf[..n])?;
        left -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_slots() {
        assert_eq!(LEN_BASE[0], 2);
        assert_eq!(LEN_BASE[7], 9);
        assert_eq!((LEN_BASE[8], LEN_BITS[8]), (10, 1));
        assert_eq!(LEN_BASE[43] as usize + (1 << LEN_BITS[43]) - 1 + 3, MAX_MATCH);
    }
}

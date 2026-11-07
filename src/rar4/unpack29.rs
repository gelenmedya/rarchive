//! The RAR 2.9 / 3.x / 4.x decoder (unpack version 29 and 36): LZ blocks with Huffman tables,
//! PPMd blocks (switched per block, with an escape for LZ-style matches), and the RarVM
//! filters, of which the standard ones are run natively.
//!
//! Provenance: the bitstream layout (block header, level table, the 299/60/17/28 symbol
//! alphabets, length/offset slot tables, end-of-block codes, PPMd escape commands, VM record
//! encoding) follows the `rars` crate (`codec/rar29.rs`, Apache-2.0) and libarchive's
//! `archive_read_support_format_rar.c` (BSD-2); the code is written for rarchive: a streaming
//! input, a ring window and filters applied on flush.

use std::io::Read;

use super::bitio::{Huff, Input};
use super::filters::{self, Kind};
use super::ppmd::Ppmd;
use super::window::Win;
use crate::error::{Error, Result};

const MAIN: usize = 299;
const OFFS: usize = 60;
const LOWS: usize = 17;
const LENS: usize = 28;
const TABLE: usize = MAIN + OFFS + LOWS + LENS;

const LBASE: [u16; LENS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; LENS] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const OBASE: [u32; OFFS] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576,
    32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872, 3670016, 3932160,
];
const OBITS: [u8; OFFS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
];
const SBASE: [u16; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// VM filter records are bounded: at most this many programs and queued filters.
const MAX_PROGRAMS: usize = 1024;
const MAX_PENDING: usize = 1024;

struct Program {
    kind: Kind,
    block_size: usize,
    exec_count: u32,
}

#[derive(Clone, Copy)]
struct Pending {
    prog: usize,
    start: u64,
    size: usize,
    regs: [u32; 7],
}

pub(super) struct Unpack29 {
    levels: [u8; TABLE],
    main: Huff,
    offs: Huff,
    lows: Huff,
    lens: Huff,
    old: [usize; 4],
    last_len: usize,
    last_dist: usize,
    low_last: usize,
    low_rep: u32,
    in_block: bool,
    ppm: bool,
    ppmd: Ppmd,
    esc: u8,
    programs: Vec<Program>,
    last_prog: usize,
    pending: Vec<Pending>,
    file_start: u64,
    tmp: Vec<u8>,
}

impl Unpack29 {
    pub(super) fn new() -> Unpack29 {
        Unpack29 {
            levels: [0; TABLE],
            main: Huff::empty(),
            offs: Huff::empty(),
            lows: Huff::empty(),
            lens: Huff::empty(),
            old: [0; 4],
            last_len: 0,
            last_dist: 0,
            low_last: 0,
            low_rep: 0,
            in_block: false,
            ppm: false,
            ppmd: Ppmd::new(),
            esc: 2,
            programs: Vec::new(),
            last_prog: 0,
            pending: Vec::new(),
            file_start: 0,
            tmp: Vec::new(),
        }
    }

    /// Model memory held by PPMd.
    pub(super) fn ppmd_memory(&self) -> usize {
        self.ppmd.memory()
    }

    pub(super) fn release(&mut self) {
        self.ppmd.release();
    }

    fn reset(&mut self) {
        self.levels = [0; TABLE];
        self.old = [0; 4];
        self.last_len = 0;
        self.last_dist = 0;
        self.low_last = 0;
        self.low_rep = 0;
        self.in_block = false;
        self.ppm = false;
        self.esc = 2;
        self.programs.clear();
        self.last_prog = 0;
        self.pending.clear();
    }

    /// Decodes one member of `size` bytes from `src`, handing the output to `out`. A non-solid
    /// member starts from scratch; `more` says a solid member follows (the block state at the
    /// end of this one then matters).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode_file(
        &mut self,
        win: &mut Win,
        inbuf: &mut Vec<u8>,
        src: &mut dyn Read,
        size: u64,
        solid: bool,
        more: bool,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if !solid {
            self.reset();
            win.reset();
        } else {
            self.pending.clear();
        }
        let mut inp = Input::new(inbuf, src);
        self.file_start = win.pos;
        let limit = win.pos + size;
        let slice = (win.size() as u64 / 4).min(1 << 20);
        while win.pos < limit {
            if !self.in_block {
                self.read_tables(&mut inp)?;
                self.in_block = true;
            }
            let end = limit.min(win.pos + slice);
            // the unflushed span (held back by a filter) plus this run must fit the ring
            let top = (end + 300).min(limit);
            if top > win.size() as u64 && top - win.written > win.size() as u64 {
                return Err(Error::Corrupt("filtered block too large"));
            }
            if self.ppm {
                self.run_ppmd(win, &mut inp, end, limit)?;
            } else {
                self.run_lz(win, &mut inp, end, limit)?;
            }
            if inp.overrun() {
                return Err(Error::Corrupt("packed data ends early"));
            }
            self.flush(win, limit, out)?;
        }
        if more {
            self.finish(&mut inp);
        }
        self.flush(win, limit, out)?;
        if !self.pending.is_empty() || win.written != win.pos {
            return Err(Error::Corrupt("filter extends past the end of the data"));
        }
        Ok(())
    }

    /// Reads the end-of-member marker so the next solid member starts in the right state
    /// (damaged markers are tolerated: the member's checksum decides).
    fn finish(&mut self, inp: &mut Input) {
        let r = (|| -> Result<()> {
            if !self.in_block {
                return Ok(());
            }
            inp.need()?;
            if self.ppm {
                let c = self.ppmd.decode(inp)?;
                if c == self.esc {
                    let n = self.ppmd.decode(inp)?;
                    if n == 0 || n == 2 {
                        self.in_block = false;
                    }
                }
            } else {
                let sym = self.main.decode(inp);
                if sym == 256 {
                    if inp.bit() {
                        self.in_block = false;
                    } else {
                        self.in_block = !inp.bit();
                    }
                }
            }
            Ok(())
        })();
        if r.is_err() {
            self.in_block = false;
        }
    }

    fn read_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.need()?;
        inp.align();
        if inp.peek32() >> 31 != 0 {
            let flags = inp.byte()?;
            self.ppm = true;
            super::count(6);
            return self.ppmd.start(inp, flags, &mut self.esc);
        }
        self.ppm = false;
        super::count(7);
        inp.skip(1);
        let keep = inp.bit();
        self.low_last = 0;
        self.low_rep = 0;
        if !keep {
            self.levels = [0; TABLE];
        }
        let mut ll = [0u8; 20];
        let mut i = 0;
        while i < 20 {
            inp.need()?;
            let v = inp.bits(4) as u8;
            if v == 15 {
                let z = inp.bits(4) as usize;
                if z == 0 {
                    ll[i] = 15;
                    i += 1;
                } else {
                    i = (i + z + 2).min(20);
                }
            } else {
                ll[i] = v;
                i += 1;
            }
        }
        let lh = Huff::new(&ll)?;
        let mut new = [0u8; TABLE];
        let mut p = 0;
        while p < TABLE {
            inp.need()?;
            let sym = lh.decode(inp);
            match sym {
                0..=15 => {
                    new[p] = (self.levels[p].wrapping_add(sym as u8)) & 15;
                    p += 1;
                }
                16 | 17 => {
                    if p == 0 {
                        return Err(Error::Corrupt("table repeat at start"));
                    }
                    let n = if sym == 16 { 3 + inp.bits(3) } else { 11 + inp.bits(7) } as usize;
                    let v = new[p - 1];
                    let e = (p + n).min(TABLE);
                    new[p..e].fill(v);
                    p = e;
                }
                18 | 19 => {
                    let n = if sym == 18 { 3 + inp.bits(3) } else { 11 + inp.bits(7) } as usize;
                    let e = (p + n).min(TABLE);
                    new[p..e].fill(0);
                    p = e;
                }
                _ => return Err(Error::Corrupt("bad code length code")),
            }
        }
        if inp.overrun() {
            return Err(Error::Corrupt("packed data ends early"));
        }
        self.levels = new;
        self.main = Huff::new(&new[..MAIN])?;
        self.offs = Huff::new(&new[MAIN..MAIN + OFFS])?;
        self.lows = Huff::new(&new[MAIN + OFFS..MAIN + OFFS + LOWS])?;
        self.lens = Huff::new(&new[MAIN + OFFS + LOWS..])?;
        Ok(())
    }

    #[inline(always)]
    fn read_len(&mut self, inp: &mut Input, base: usize) -> Result<usize> {
        let slot = self.lens.decode(inp) as usize;
        if slot >= LENS {
            return Err(Error::Corrupt("bad length code"));
        }
        let mut len = LBASE[slot] as usize + base;
        let b = LBITS[slot] as u32;
        if b != 0 {
            len += inp.bits(b) as usize;
        }
        Ok(len)
    }

    #[inline(always)]
    fn read_offset(&mut self, inp: &mut Input) -> Result<usize> {
        let slot = self.offs.decode(inp) as usize;
        if slot >= OFFS {
            return Err(Error::Corrupt("bad offset code"));
        }
        let mut off = OBASE[slot] as usize + 1;
        let eb = OBITS[slot] as u32;
        if eb != 0 {
            if slot > 9 {
                if eb > 4 {
                    off += (inp.bits(eb - 4) as usize) << 4;
                }
                if self.low_rep > 0 {
                    self.low_rep -= 1;
                    off += self.low_last;
                } else {
                    let low = self.lows.decode(inp);
                    if low == 16 {
                        self.low_rep = 15;
                        off += self.low_last;
                    } else if low < 16 {
                        self.low_last = low as usize;
                        off += low as usize;
                    } else {
                        return Err(Error::Corrupt("bad low offset code"));
                    }
                }
            } else {
                off += inp.bits(eb) as usize;
            }
        }
        Ok(off)
    }

    fn run_lz(&mut self, win: &mut Win, inp: &mut Input, end: u64, limit: u64) -> Result<()> {
        while win.pos < end {
            inp.need()?;
            let sym = self.main.decode(inp);
            if sym < 256 {
                win.put(sym as u8);
                continue;
            }
            let (len, dist) = match sym {
                256 => return self.end_of_block(inp),
                257 => {
                    self.read_vm_lz(win, inp)?;
                    continue;
                }
                258 => {
                    if self.last_len == 0 {
                        continue;
                    }
                    (self.last_len, self.last_dist)
                }
                259..=262 => {
                    let idx = (sym - 259) as usize;
                    let dist = self.old[idx];
                    let len = self.read_len(inp, 2)?;
                    for i in (1..=idx).rev() {
                        self.old[i] = self.old[i - 1];
                    }
                    self.old[0] = dist;
                    self.last_dist = dist;
                    self.last_len = len;
                    (len, dist)
                }
                263..=270 => {
                    let idx = (sym - 263) as usize;
                    let dist = SBASE[idx] as usize + 1 + inp.bits(SBITS[idx] as u32) as usize;
                    self.push_old(dist);
                    self.last_dist = dist;
                    self.last_len = 2;
                    (2, dist)
                }
                271..=298 => {
                    let slot = (sym - 271) as usize;
                    let mut len = LBASE[slot] as usize + 3;
                    let b = LBITS[slot] as u32;
                    if b != 0 {
                        len += inp.bits(b) as usize;
                    }
                    let dist = self.read_offset(inp)?;
                    if dist >= 0x2000 {
                        len += 1;
                    }
                    if dist >= 0x40000 {
                        len += 1;
                    }
                    self.push_old(dist);
                    self.last_dist = dist;
                    self.last_len = len;
                    (len, dist)
                }
                _ => return Err(Error::Corrupt("bad symbol")),
            };
            if len as u64 > limit - win.pos || !win.copy(dist, len) {
                return Err(Error::Corrupt("bad match"));
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn push_old(&mut self, dist: usize) {
        self.old = [dist, self.old[0], self.old[1], self.old[2]];
    }

    /// After a 256 symbol inside a member: either a new table follows in the same member, or
    /// the member would end here (an error: it has more data to produce).
    fn end_of_block(&mut self, inp: &mut Input) -> Result<()> {
        if inp.bit() {
            self.in_block = false;
            Ok(())
        } else {
            let _ = inp.bit();
            Err(Error::Corrupt("member ends before its declared size"))
        }
    }

    fn run_ppmd(&mut self, win: &mut Win, inp: &mut Input, end: u64, limit: u64) -> Result<()> {
        while win.pos < end {
            let c = self.ppmd.decode(inp)?;
            if c != self.esc {
                win.put(c);
                continue;
            }
            let n = self.ppmd.decode(inp)?;
            match n {
                0 => {
                    self.in_block = false;
                    return Ok(());
                }
                1 => win.put(self.esc),
                2 => return Err(Error::Corrupt("member ends before its declared size")),
                3 => self.read_vm_ppmd(win, inp)?,
                4 => {
                    let mut off = 0usize;
                    for _ in 0..3 {
                        off = (off << 8) | self.ppmd.decode(inp)? as usize;
                    }
                    let len = self.ppmd.decode(inp)? as usize + 32;
                    if len as u64 > limit - win.pos || !win.copy(off + 2, len) {
                        return Err(Error::Corrupt("bad match"));
                    }
                }
                5 => {
                    let len = self.ppmd.decode(inp)? as usize + 4;
                    if len as u64 > limit - win.pos || !win.copy(1, len) {
                        return Err(Error::Corrupt("bad match"));
                    }
                }
                _ => return Err(Error::Corrupt("bad PPMd command")),
            }
        }
        Ok(())
    }

    fn read_vm_lz(&mut self, win: &Win, inp: &mut Input) -> Result<()> {
        inp.need()?;
        let first = inp.bits(8) as usize;
        let mut len = (first & 7) + 1;
        if len == 7 {
            len = inp.bits(8) as usize + 7;
        } else if len == 8 {
            len = inp.bits(16) as usize;
        }
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            inp.need()?;
            data.push(inp.bits(8) as u8);
        }
        self.parse_vm(win, first as u8, &data)
    }

    fn read_vm_ppmd(&mut self, win: &Win, inp: &mut Input) -> Result<()> {
        let first = self.ppmd.decode(inp)? as usize;
        let mut len = (first & 7) + 1;
        if len == 7 {
            len = self.ppmd.decode(inp)? as usize + 7;
        } else if len == 8 {
            len = (self.ppmd.decode(inp)? as usize) << 8;
            len |= self.ppmd.decode(inp)? as usize;
        }
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(self.ppmd.decode(inp)?);
        }
        self.parse_vm(win, first as u8, &data)
    }

    /// Reads a filter record (the RarVM "add code" structure).
    fn parse_vm(&mut self, win: &Win, first: u8, data: &[u8]) -> Result<()> {
        let mut b = VmBits { d: data, pos: 0 };
        let idx = if first & 0x80 != 0 {
            let v = b.encoded()?;
            if v == 0 {
                self.programs.clear();
                self.pending.clear();
                0
            } else {
                (v - 1) as usize
            }
        } else {
            self.last_prog
        };
        if idx > self.programs.len() {
            return Err(Error::Corrupt("filter program index"));
        }
        self.last_prog = idx;
        let new = idx == self.programs.len();
        let mut start = b.encoded()? as u64;
        if first & 0x40 != 0 {
            start += 258;
        }
        let start = win.pos + start;
        let mut size = self.programs.get(idx).map_or(0, |p| p.block_size);
        if first & 0x20 != 0 {
            size = b.encoded()? as usize;
        }
        if size > 0x100000 {
            return Err(Error::Corrupt("filter block size"));
        }
        let mut regs = [0u32; 7];
        regs[3] = 0x3c000;
        regs[4] = size as u32;
        if let Some(p) = self.programs.get(idx) {
            regs[5] = p.exec_count;
        }
        if first & 0x10 != 0 {
            let mask = b.bits(7)?;
            for (i, r) in regs.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *r = b.encoded()?;
                }
            }
        }
        if new {
            if self.programs.len() >= MAX_PROGRAMS {
                return Err(Error::Corrupt("too many filter programs"));
            }
            let n = b.encoded()? as usize;
            if n == 0 || n >= 0x10000 {
                return Err(Error::Corrupt("filter code size"));
            }
            let mut code = Vec::with_capacity(n);
            for _ in 0..n {
                code.push(b.bits(8)? as u8);
            }
            let Some(kind) = filters::identify(&code) else {
                return Err(Error::Unsupported("custom RAR filter program"));
            };
            self.programs.push(Program { kind, block_size: size, exec_count: 0 });
        } else {
            let p = &mut self.programs[idx];
            p.exec_count = p.exec_count.wrapping_add(1);
            p.block_size = size;
        }
        // global data: not used by the standard filters
        if first & 0x08 != 0 {
            let n = b.encoded()? as usize;
            if n > 0x2000 - 64 {
                return Err(Error::Corrupt("filter global data"));
            }
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::Corrupt("too many queued filters"));
        }
        self.pending.push(Pending { prog: idx, start, size, regs });
        Ok(())
    }

    /// Hands out what is final: plain data up to the next filter block, and finished filter
    /// blocks.
    fn flush(&mut self, win: &mut Win, limit: u64, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        loop {
            let Some(f) = self.pending.first().copied() else {
                win.emit(win.written, win.pos, out)?;
                win.written = win.pos;
                return Ok(());
            };
            if f.start < win.written {
                return Err(Error::Corrupt("overlapping filters"));
            }
            if f.start > win.written {
                let to = f.start.min(win.pos);
                win.emit(win.written, to, out)?;
                win.written = to;
                if to < f.start {
                    return Ok(());
                }
            }
            let end = f.start + f.size as u64;
            if end > limit {
                return Err(Error::Corrupt("filter extends past the end of the data"));
            }
            if end > win.pos {
                return Ok(());
            }
            let mut data = std::mem::take(&mut self.tmp);
            data.clear();
            win.gather(f.start, end, &mut data);
            let file_offset = (f.start - self.file_start) as u32;
            let mut cur = f;
            loop {
                let kind = self.programs.get(cur.prog).map(|p| p.kind).ok_or(Error::Corrupt("filter program"))?;
                filters::apply(kind, &mut data, file_offset, &cur.regs)?;
                self.pending.remove(0);
                match self.pending.first() {
                    Some(n) if n.start == f.start && n.size == data.len() => cur = *n,
                    _ => break,
                }
            }
            let r = out(&data);
            self.tmp = data;
            r?;
            win.written = end;
        }
    }
}

/// MSB-first bits of a filter record.
struct VmBits<'a> {
    d: &'a [u8],
    pos: usize,
}

impl VmBits<'_> {
    fn bits(&mut self, n: usize) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.d.get(self.pos >> 3).ok_or(Error::Corrupt("filter record"))?;
            v = (v << 1) | u32::from((byte >> (7 - (self.pos & 7))) & 1);
            self.pos += 1;
        }
        Ok(v)
    }

    fn encoded(&mut self) -> Result<u32> {
        Ok(match self.bits(2)? {
            0 => self.bits(4)?,
            1 => {
                let hi = self.bits(8)?;
                if hi >= 16 { hi } else { 0xffff_ff00 | (hi << 4) | self.bits(4)? }
            }
            2 => self.bits(16)?,
            _ => (self.bits(16)? << 16) | self.bits(16)?,
        })
    }
}


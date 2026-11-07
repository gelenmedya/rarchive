//! Streaming MSB-first bit input and canonical Huffman tables for the RAR 1.5-4 decoders.
//!
//! Provenance: written for rarchive from the public description of the format (RARLAB technote,
//! libarchive's `archive_read_support_format_rar.c` for the table shapes); only the idea of
//! a refill-on-demand window is shared with `crate::bits`.

use std::io::Read;

use crate::error::{Error, Result};

/// Bytes kept readable (as zeros) past the end of the data.
pub(super) const PAD: usize = 64;
const CAP: usize = 256 << 10;

/// Packed data, read through a refillable buffer. Reads past the end of the data see zeros;
/// `finish` tells whether that happened (damaged or truncated data).
pub(super) struct Input<'a> {
    buf: &'a mut Vec<u8>,
    src: &'a mut dyn Read,
    /// Position of the next bit.
    pub(super) pos: usize,
    /// Valid bytes in `buf`.
    len: usize,
    eof: bool,
}

impl<'a> Input<'a> {
    pub(super) fn new(buf: &'a mut Vec<u8>, src: &'a mut dyn Read) -> Input<'a> {
        if buf.len() < CAP + PAD {
            buf.resize(CAP + PAD, 0);
        }
        let i = Input { buf, src, pos: 0, len: 0, eof: false };
        i.buf[..PAD].fill(0);
        i
    }

    #[cold]
    #[inline(never)]
    fn fill(&mut self) -> Result<()> {
        if self.eof {
            if (self.pos >> 3) > self.len + 24 {
                return Err(Error::Corrupt("packed data ends early"));
            }
            return Ok(());
        }
        let keep_from = self.pos >> 3;
        let keep = self.len.saturating_sub(keep_from);
        if keep_from > 0 && keep_from <= self.len {
            self.buf.copy_within(keep_from..self.len, 0);
            self.pos -= keep_from * 8;
        } else if keep_from > self.len {
            // already past the data (can't happen before eof)
            self.pos -= self.len * 8;
        }
        self.len = keep;
        while self.len < CAP {
            let n = self.src.read(&mut self.buf[self.len..CAP]).map_err(Error::from)?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.len += n;
        }
        self.buf[self.len..self.len + PAD].fill(0);
        Ok(())
    }

    /// Makes sure at least 16 bytes (or all that is left, then zeros) can be read.
    #[inline(always)]
    pub(super) fn need(&mut self) -> Result<()> {
        if (self.pos >> 3) + 16 > self.len { self.fill() } else { Ok(()) }
    }

    /// The next 32 bits (valid for 25 bits after any bit offset).
    #[inline(always)]
    pub(super) fn peek32(&self) -> u32 {
        let p = (self.pos >> 3).min(self.buf.len() - 8);
        // SAFETY: p + 8 <= buf.len() (p is clamped just above; buf holds at least CAP + PAD bytes)
        let v = u64::from_be_bytes(unsafe { self.buf.as_ptr().add(p).cast::<[u8; 8]>().read_unaligned() });
        ((v << (self.pos & 7)) >> 32) as u32
    }

    #[inline(always)]
    pub(super) fn skip(&mut self, n: u32) {
        self.pos += n as usize;
    }

    /// Reads `n` bits (0..=25) the last `need` made available.
    #[inline(always)]
    pub(super) fn bits(&mut self, n: u32) -> u32 {
        let v = (u64::from(self.peek32()) >> (32 - n)) as u32;
        self.pos += n as usize;
        v
    }

    #[inline(always)]
    pub(super) fn bit(&mut self) -> bool {
        self.bits(1) != 0
    }

    pub(super) fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }

    /// A whole byte (the stream is read byte-wise by PPMd).
    #[inline(always)]
    pub(super) fn byte(&mut self) -> Result<u8> {
        self.need()?;
        Ok(self.bits(8) as u8)
    }

    /// Whether more bits were read than the data holds.
    pub(super) fn overrun(&self) -> bool {
        self.eof && self.pos > self.len * 8
    }

    /// Bits left in the data (0 when overrun).
    pub(super) fn bits_left(&self) -> usize {
        (self.len * 8).saturating_sub(self.pos)
    }
}

/// Longest code, in bits.
pub(super) const MAX_LEN: usize = 15;
const LB: u32 = 10;
/// Returned for a bit pattern that starts no code.
pub(super) const INVALID: u32 = 0xFFFF;

/// A canonical Huffman code (shorter codes first, equal lengths in symbol order).
pub(super) struct Huff {
    lut: Vec<u16>,
    /// First code of each length, left-aligned to 15 bits.
    first: [u32; MAX_LEN + 2],
    /// Index into `symbols` of each length's first symbol.
    index: [u16; MAX_LEN + 2],
    symbols: Vec<u16>,
}

impl Huff {
    pub(super) fn empty() -> Huff {
        Huff { lut: vec![0; 1 << LB], first: [0; MAX_LEN + 2], index: [0; MAX_LEN + 2], symbols: Vec::new() }
    }

    pub(super) fn new(lengths: &[u8]) -> Result<Huff> {
        let mut count = [0u32; MAX_LEN + 1];
        for &l in lengths {
            count[(l as usize).min(MAX_LEN)] += 1;
        }
        count[0] = 0;
        let mut space: i64 = 1 << MAX_LEN;
        for len in 1..=MAX_LEN {
            space -= (count[len] as i64) << (MAX_LEN - len);
        }
        if space < 0 {
            return Err(Error::Corrupt("oversubscribed Huffman table"));
        }
        let mut h = Huff { lut: vec![0; 1 << LB], first: [0; MAX_LEN + 2], index: [0; MAX_LEN + 2], symbols: vec![0; lengths.len()] };
        let mut next = [0u32; MAX_LEN + 1];
        let mut code = 0u32;
        let mut idx = 0u16;
        for len in 1..=MAX_LEN {
            next[len] = code;
            h.first[len] = code << (MAX_LEN - len);
            h.index[len] = idx;
            idx += count[len] as u16;
            code = (code + count[len]) << 1;
        }
        h.first[MAX_LEN + 1] = 1 << MAX_LEN;
        h.index[MAX_LEN + 1] = idx;
        h.symbols.truncate(idx as usize);
        let mut slot = h.index;
        for (sym, &l) in lengths.iter().enumerate() {
            let len = l as usize;
            if len == 0 || len > MAX_LEN {
                continue;
            }
            h.symbols[slot[len] as usize] = sym as u16;
            slot[len] += 1;
            let c = next[len];
            next[len] += 1;
            if len as u32 <= LB {
                let shift = LB - len as u32;
                let start = (c << shift) as usize;
                let e = (sym as u16) << 4 | len as u16;
                h.lut[start..start + (1usize << shift)].fill(e);
            }
        }
        Ok(h)
    }

    #[inline(always)]
    pub(super) fn decode(&self, inp: &mut Input) -> u32 {
        let v = inp.peek32() >> 17; // 15 bits
        // SAFETY: lut always holds 1 << LB entries and the index is a 15-bit value shifted down
        let e = unsafe { *self.lut.get_unchecked((v >> (MAX_LEN as u32 - LB)) as usize) };
        if e != 0 {
            inp.skip((e & 15) as u32);
            return u32::from(e >> 4);
        }
        self.decode_long(inp, v)
    }

    #[cold]
    #[inline(never)]
    fn decode_long(&self, inp: &mut Input, v: u32) -> u32 {
        for len in LB as usize + 1..=MAX_LEN {
            // codes of this length start at first[len] and span (count << (15 - len))
            let count = u32::from(self.index[len + 1] - self.index[len]);
            let span = count << (MAX_LEN - len);
            if v >= self.first[len] && v - self.first[len] < span {
                let i = u32::from(self.index[len]) + ((v - self.first[len]) >> (MAX_LEN - len));
                inp.skip(len as u32);
                return u32::from(self.symbols[i as usize]);
            }
        }
        INVALID
    }
}

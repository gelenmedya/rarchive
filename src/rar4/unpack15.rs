//! The RAR 1.5 decoder (unpack version 15): adaptive Huffman coding of literals (character
//! sets re-ranked as they are used), short and long LZ matches, and a "static" mode.
//!
//! Provenance: the model (the decode tables, rank sets, the averages that pick a table, the
//! flag byte scheme) follows the `rars` crate's `codec/rar13.rs` (Apache-2.0), itself written
//! from the format description; the code is written for rarchive over a streaming input and the
//! shared ring window (64 KB of it matter here).

use std::io::Read;

use super::bitio::Input;
use super::window::Win;
use crate::error::{Error, Result};

const DEC_L1: &[u16] = &[0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff];
const POS_L1: &[u16] = &[0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: &[u16] = &[0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff];
const POS_L2: &[u16] = &[0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: &[u16] = &[0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff];
const POS_HF0: &[u16] = &[0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: &[u16] = &[0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff];
const POS_HF1: &[u16] = &[0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: &[u16] = &[0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff];
const POS_HF2: &[u16] = &[0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: &[u16] = &[0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: &[u16] = &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u8; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u8; 15] = [0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];
const SHORT_LEN2: [u8; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u8; 15] = [0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];

pub(super) struct Unpack15 {
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    buf60: u32,
    st_mode: bool,
    l_count: u32,
    flag_buf: u32,
    flags_cnt: i32,
    old_dist: [u32; 4],
    old_ptr: usize,
    last_dist: u32,
    last_len: u32,
    /// Bytes left to produce in the member.
    limit: u64,
}

impl Unpack15 {
    pub(super) fn new() -> Unpack15 {
        let mut u = Unpack15 {
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0,
            nhfb: 0,
            nlzb: 0,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [0; 4],
            old_ptr: 0,
            last_dist: 0,
            last_len: 0,
            limit: 0,
        };
        u.reset();
        u
    }

    fn reset(&mut self) {
        self.avr_plc_b = 0;
        self.avr_ln1 = 0;
        self.avr_ln2 = 0;
        self.avr_ln3 = 0;
        self.num_huf = 0;
        self.buf60 = 0;
        self.avr_plc = 0x3500;
        self.max_dist3 = 0x2001;
        self.nhfb = 0x80;
        self.nlzb = 0x80;
        self.old_dist = [u32::MAX; 4];
        self.old_ptr = 0;
        self.last_dist = u32::MAX;
        self.last_len = 0;
        for i in 0..256usize {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
            self.ch_set_a[i] = i as u16;
            self.ch_set_c[i] = (0u8.wrapping_sub(i as u8) as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    pub(super) fn decode_file(
        &mut self,
        win: &mut Win,
        inbuf: &mut Vec<u8>,
        src: &mut dyn Read,
        size: u64,
        solid: bool,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.flags_cnt = -2;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;
        if !solid {
            self.reset();
            win.reset();
        }
        let mut inp = Input::new(inbuf, src);
        let limit = win.pos + size;
        self.limit = limit;
        let slice = (win.size() as u64 / 4).min(1 << 20);
        while win.pos < limit {
            let end = limit.min(win.pos + slice);
            while win.pos < end {
                inp.need()?;
                self.step(win, &mut inp)?;
            }
            if inp.overrun() {
                return Err(Error::Corrupt("packed data ends early"));
            }
            win.emit(win.written, win.pos, out)?;
            win.written = win.pos;
        }
        Ok(())
    }

    #[inline(always)]
    fn bits16(inp: &Input) -> u32 {
        inp.peek32() >> 16
    }

    fn step(&mut self, win: &mut Win, inp: &mut Input) -> Result<()> {
        if self.flags_cnt == -2 {
            self.get_flags(inp);
            self.flags_cnt = 8;
        }
        if self.st_mode {
            return self.huff_decode(win, inp);
        }
        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags(inp);
            self.flags_cnt = 7;
        }
        if self.flag_buf & 0x80 != 0 {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            if self.nlzb > self.nhfb { self.long_lz(win, inp) } else { self.huff_decode(win, inp) }
        } else {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            self.flags_cnt -= 1;
            if self.flags_cnt < 0 {
                self.get_flags(inp);
                self.flags_cnt = 7;
            }
            if self.flag_buf & 0x80 != 0 {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                if self.nlzb > self.nhfb { self.huff_decode(win, inp) } else { self.long_lz(win, inp) }
            } else {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                self.short_lz(win, inp)
            }
        }
    }

    fn short_len1(&self, pos: usize) -> u32 {
        if pos == 1 { self.buf60 + 3 } else { u32::from(SHORT_LEN1[pos]) }
    }

    fn short_len2(&self, pos: usize) -> u32 {
        if pos == 3 { self.buf60 + 3 } else { u32::from(SHORT_LEN2[pos]) }
    }

    fn short_lz(&mut self, win: &mut Win, inp: &mut Input) -> Result<()> {
        self.num_huf = 0;
        let mut field = Self::bits16(inp);
        if self.l_count == 2 {
            inp.skip(1);
            if field >= 0x8000 {
                return self.copy(win, self.last_dist, self.last_len);
            }
            field = (field << 1) & 0xffff;
            self.l_count = 0;
        }
        let bb = (field >> 8) as u8;
        let mut length = 0usize;
        if self.avr_ln1 < 37 {
            loop {
                let sl = self.short_len1(length);
                let mask = (!(0xffu16 >> sl)) as u8;
                if ((bb ^ SHORT_XOR1[length]) & mask) == 0 {
                    break;
                }
                length += 1;
                if length >= 15 {
                    return Err(Error::Corrupt("bad short code"));
                }
            }
            inp.skip(self.short_len1(length));
        } else {
            loop {
                let sl = self.short_len2(length);
                let mask = (!(0xffu16 >> sl)) as u8;
                if ((bb ^ SHORT_XOR2[length]) & mask) == 0 {
                    break;
                }
                length += 1;
                if length >= 15 {
                    return Err(Error::Corrupt("bad short code"));
                }
            }
            inp.skip(self.short_len2(length));
        }
        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                return self.copy(win, self.last_dist, self.last_len);
            }
            if length == 14 {
                self.l_count = 0;
                length = Self::decode_num(inp, Self::bits16(inp), 3, DEC_L2, POS_L2) + 5;
                let dist = (Self::bits16(inp) >> 1) | 0x8000;
                inp.skip(15);
                self.last_len = length;
                self.last_dist = dist;
                return self.copy(win, dist, length);
            }
            self.l_count = 0;
            let save = length;
            let dist = self.old_dist[self.old_ptr.wrapping_sub((length - 9) as usize) & 3];
            length = Self::decode_num(inp, Self::bits16(inp), 2, DEC_L1, POS_L1) + 2;
            if length == 0x101 && save == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if dist > 256 {
                length += 1;
            }
            if dist >= self.max_dist3 {
                length += 1;
            }
            self.remember(dist, length);
            return self.copy(win, dist, length);
        }
        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;
        let place = (Self::decode_num(inp, Self::bits16(inp), 5, DEC_HF2, POS_HF2) & 0xff) as usize;
        let mut dist = u32::from(self.ch_set_a[place]);
        if place > 0 {
            let last = self.ch_set_a[place - 1];
            self.ch_set_a[place] = last;
            self.ch_set_a[place - 1] = dist as u16;
        }
        length += 2;
        dist += 1;
        self.remember(dist, length);
        self.copy(win, dist, length)
    }

    fn long_lz(&mut self, win: &mut Win, inp: &mut Input) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;
        let field = Self::bits16(inp);
        let mut length = if self.avr_ln2 >= 122 {
            Self::decode_num(inp, field, 3, DEC_L2, POS_L2)
        } else if self.avr_ln2 >= 64 {
            Self::decode_num(inp, field, 2, DEC_L1, POS_L1)
        } else if field < 0x100 {
            inp.skip(16);
            field
        } else {
            let mut l = 0u32;
            while ((field << l) & 0x8000) == 0 {
                l += 1;
            }
            inp.skip(l + 1);
            l
        };
        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let field = Self::bits16(inp);
        let place = if self.avr_plc_b > 0x28ff {
            Self::decode_num(inp, field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            Self::decode_num(inp, field, 5, DEC_HF1, POS_HF1)
        } else {
            Self::decode_num(inp, field, 4, DEC_HF0, POS_HF0)
        };
        self.avr_plc_b += place;
        self.avr_plc_b -= self.avr_plc_b >> 8;
        let idx = (place & 0xff) as usize;
        let mut dist;
        let new_place;
        loop {
            dist = u32::from(self.ch_set_b[idx]);
            let np = self.n_to_pl_b[(dist & 0xff) as usize] as usize;
            self.n_to_pl_b[(dist & 0xff) as usize] = self.n_to_pl_b[(dist & 0xff) as usize].wrapping_add(1);
            dist += 1;
            if dist & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                new_place = np;
                break;
            }
        }
        self.ch_set_b[idx] = self.ch_set_b[new_place];
        self.ch_set_b[new_place] = dist as u16;
        dist = ((dist & 0xff00) | (Self::bits16(inp) >> 8)) >> 1;
        inp.skip(7);
        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && dist <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if dist >= self.max_dist3 {
            length += 1;
        }
        if dist <= 256 {
            length += 8;
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }
        self.remember(dist, length);
        self.copy(win, dist, length)
    }

    fn huff_decode(&mut self, win: &mut Win, inp: &mut Input) -> Result<()> {
        let field = Self::bits16(inp);
        let mut place = if self.avr_plc > 0x75ff {
            Self::decode_num(inp, field, 8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            Self::decode_num(inp, field, 6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            Self::decode_num(inp, field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            Self::decode_num(inp, field, 5, DEC_HF1, POS_HF1)
        } else {
            Self::decode_num(inp, field, 4, DEC_HF0, POS_HF0)
        } & 0xff;
        if self.st_mode {
            if place == 0 && field > 0x0fff {
                place = 0x100;
            }
            if place == 0 {
                let f = Self::bits16(inp);
                inp.skip(1);
                if f & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }
                let length = if f & 0x4000 != 0 { 4 } else { 3 };
                inp.skip(1);
                let mut dist = Self::decode_num(inp, Self::bits16(inp), 5, DEC_HF2, POS_HF2);
                dist = (dist << 5) | (Self::bits16(inp) >> 11);
                inp.skip(5);
                return self.copy(win, dist, length);
            }
            place -= 1;
        } else {
            if self.num_huf >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
            self.num_huf += 1;
        }
        self.avr_plc += place;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        let byte = (self.ch_set[place as usize] >> 8) as u8;
        self.put(win, byte)?;
        let idx = place as usize;
        let mut cur;
        let new_place;
        loop {
            cur = u32::from(self.ch_set[idx]);
            let np = self.n_to_pl[(cur & 0xff) as usize] as usize;
            self.n_to_pl[(cur & 0xff) as usize] = self.n_to_pl[(cur & 0xff) as usize].wrapping_add(1);
            cur += 1;
            if cur & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                new_place = np;
                break;
            }
        }
        self.ch_set[idx] = self.ch_set[new_place];
        self.ch_set[new_place] = cur as u16;
        Ok(())
    }

    fn get_flags(&mut self, inp: &mut Input) {
        let place = Self::decode_num(inp, Self::bits16(inp), 5, DEC_HF2, POS_HF2) as usize;
        if place >= 256 {
            return;
        }
        let mut flags;
        let new_place;
        loop {
            flags = u32::from(self.ch_set_c[place]);
            let np = self.n_to_pl_c[(flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(flags & 0xff) as usize] = self.n_to_pl_c[(flags & 0xff) as usize].wrapping_add(1);
            self.flag_buf = flags >> 8;
            flags += 1;
            if flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                new_place = np;
                break;
            }
        }
        self.ch_set_c[place] = self.ch_set_c[new_place];
        self.ch_set_c[new_place] = flags as u16;
    }

    fn decode_num(inp: &mut Input, num: u32, mut start: u32, dec: &[u16], pos: &[u16]) -> u32 {
        let num = num & 0xfff0;
        let mut i = 0usize;
        while u32::from(dec[i]) <= num {
            start += 1;
            i += 1;
        }
        inp.skip(start);
        ((num - if i > 0 { u32::from(dec[i - 1]) } else { 0 }) >> (16 - start)) + u32::from(pos[start as usize])
    }

    fn put(&mut self, win: &mut Win, b: u8) -> Result<()> {
        if win.pos >= self.limit {
            return Err(Error::Corrupt("data past the end of the member"));
        }
        win.put(b);
        Ok(())
    }

    fn copy(&mut self, win: &mut Win, dist: u32, len: u32) -> Result<()> {
        if u64::from(len) > self.limit - win.pos {
            return Err(Error::Corrupt("bad match"));
        }
        let (dist, len) = (dist as usize, len as usize);
        if dist == 0 || dist > 0x10000 || dist as u64 > win.pos {
            // reaches outside the window: the window held zeros there
            for _ in 0..len {
                win.put(0);
            }
        } else if !win.copy(dist, len) {
            return Err(Error::Corrupt("bad match"));
        }
        Ok(())
    }

    fn remember(&mut self, dist: u32, len: u32) {
        self.old_dist[self.old_ptr] = dist;
        self.old_ptr = (self.old_ptr + 1) & 3;
        self.last_len = len;
        self.last_dist = dist;
    }
}

fn corr_huff(set: &mut [u16; 256], to_place: &mut [u8; 256]) {
    let mut pos = 0usize;
    for rank in (0..=7u16).rev() {
        for _ in 0..32 {
            set[pos] = (set[pos] & !0xff) | rank;
            pos += 1;
        }
    }
    *to_place = [0; 256];
    for rank in (0..=6usize).rev() {
        to_place[rank] = ((7 - rank) * 32) as u8;
    }
}

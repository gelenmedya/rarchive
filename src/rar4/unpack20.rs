//! The RAR 2.0 decoder (unpack version 20 / 26): LZ blocks with Huffman tables and the
//! multimedia (audio) mode that predicts samples per channel.
//!
//! Provenance: bitstream layout (table header bits, 19-symbol level table, the 298/48/28
//! alphabets, old-offset handling, audio predictor) follows the `rars` crate's
//! `codec/rar20.rs` (Apache-2.0); the code is written for rarchive over a streaming input and the
//! shared ring window.

use std::io::Read;

use super::bitio::{Huff, Input};
use super::window::Win;
use crate::error::{Error, Result};

const MAIN: usize = 298;
const OFFS: usize = 48;
const LENS: usize = 28;
const TABLE: usize = MAIN + OFFS + LENS;
const AUDIO: usize = 257;
const LEVELS: usize = AUDIO * 4;

const LBASE: [u16; LENS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; LENS] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const OBASE: [u32; OFFS] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576,
    32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const OBITS: [u8; OFFS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16,
];
const SBASE: [u16; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

#[derive(Clone, Copy, Default)]
struct AudioState {
    k: [i32; 5],
    d: [i32; 4],
    last_delta: i32,
    last_char: i32,
    count: u32,
    dif: [u32; 11],
}

pub(super) struct Unpack20 {
    levels: [u8; LEVELS],
    main: Huff,
    offs: Huff,
    lens: Huff,
    audio_tables: [Huff; 4],
    audio_block: bool,
    channels: usize,
    cur: usize,
    audio: [AudioState; 4],
    channel_delta: i32,
    old: [usize; 4],
    last_dist: usize,
    last_len: usize,
    in_block: bool,
}

impl Unpack20 {
    pub(super) fn new() -> Unpack20 {
        Unpack20 {
            levels: [0; LEVELS],
            main: Huff::empty(),
            offs: Huff::empty(),
            lens: Huff::empty(),
            audio_tables: [Huff::empty(), Huff::empty(), Huff::empty(), Huff::empty()],
            audio_block: false,
            channels: 1,
            cur: 0,
            audio: [AudioState::default(); 4],
            channel_delta: 0,
            old: [0; 4],
            last_dist: 0,
            last_len: 0,
            in_block: false,
        }
    }

    fn reset(&mut self) {
        self.levels = [0; LEVELS];
        self.audio_block = false;
        self.channels = 1;
        self.cur = 0;
        self.audio = [AudioState::default(); 4];
        self.channel_delta = 0;
        self.old = [0; 4];
        self.last_dist = 0;
        self.last_len = 0;
        self.in_block = false;
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
        if !solid {
            self.reset();
            win.reset();
        }
        let mut inp = Input::new(inbuf, src);
        let limit = win.pos + size;
        let slice = (win.size() as u64 / 4).min(1 << 20);
        while win.pos < limit {
            if !self.in_block {
                self.read_tables(&mut inp)?;
                self.in_block = true;
            }
            let end = limit.min(win.pos + slice);
            if self.audio_block {
                self.run_audio(win, &mut inp, end)?;
            } else {
                self.run_lz(win, &mut inp, end, limit)?;
            }
            if inp.overrun() {
                return Err(Error::Corrupt("packed data ends early"));
            }
            win.emit(win.written, win.pos, out)?;
            win.written = win.pos;
        }
        // a solid member that follows continues with whatever table the stream announces now
        let _ = self.read_last_tables(&mut inp);
        Ok(())
    }

    fn read_last_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.need()?;
        if inp.bits_left() < 40 {
            return Ok(());
        }
        let sym = if self.audio_block { self.audio_tables[self.cur].decode(inp) } else { self.main.decode(inp) };
        if (self.audio_block && sym == 256) || (!self.audio_block && sym == 269) {
            self.read_tables(inp)?;
            self.in_block = true;
        }
        Ok(())
    }

    fn read_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.need()?;
        let field = inp.peek32() >> 16;
        self.audio_block = field & 0x8000 != 0;
        let keep = field & 0x4000 != 0;
        inp.skip(2);
        if !keep {
            self.levels = [0; LEVELS];
        }
        let total = if self.audio_block {
            self.channels = ((field >> 12) as usize & 3) + 1;
            if self.cur >= self.channels {
                self.cur = 0;
            }
            inp.skip(2);
            AUDIO * self.channels
        } else {
            TABLE
        };
        let mut ll = [0u8; 19];
        for l in &mut ll {
            inp.need()?;
            *l = inp.bits(4) as u8;
        }
        let lh = Huff::new(&ll)?;
        let mut new = [0u8; LEVELS];
        let mut p = 0;
        while p < total {
            inp.need()?;
            let sym = lh.decode(inp);
            match sym {
                0..=15 => {
                    new[p] = (self.levels[p].wrapping_add(sym as u8)) & 15;
                    p += 1;
                }
                16 => {
                    if p == 0 {
                        return Err(Error::Corrupt("table repeat at start"));
                    }
                    let n = 3 + inp.bits(2) as usize;
                    let v = new[p - 1];
                    let e = (p + n).min(total);
                    new[p..e].fill(v);
                    p = e;
                }
                17 | 18 => {
                    let n = if sym == 17 { 3 + inp.bits(3) } else { 11 + inp.bits(7) } as usize;
                    let e = (p + n).min(total);
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
        if self.audio_block {
            for c in 0..self.channels {
                self.audio_tables[c] = Huff::new(&new[c * AUDIO..(c + 1) * AUDIO])?;
            }
        } else {
            self.main = Huff::new(&new[..MAIN])?;
            self.offs = Huff::new(&new[MAIN..MAIN + OFFS])?;
            self.lens = Huff::new(&new[MAIN + OFFS..TABLE])?;
        }
        Ok(())
    }

    fn run_audio(&mut self, win: &mut Win, inp: &mut Input, end: u64) -> Result<()> {
        while win.pos < end {
            inp.need()?;
            let sym = self.audio_tables[self.cur].decode(inp);
            if sym == 256 {
                self.in_block = false;
                return Ok(());
            }
            if sym > 255 {
                return Err(Error::Corrupt("bad audio symbol"));
            }
            let b = self.audio_byte(sym as u8);
            win.put(b);
            self.cur += 1;
            if self.cur == self.channels {
                self.cur = 0;
            }
        }
        Ok(())
    }

    fn audio_byte(&mut self, delta: u8) -> u8 {
        let st = &mut self.audio[self.cur];
        st.count = st.count.wrapping_add(1);
        st.d[3] = st.d[2];
        st.d[2] = st.d[1];
        st.d[1] = st.last_delta - st.d[0];
        st.d[0] = st.last_delta;
        let pred = 8 * st.last_char + st.k[0] * st.d[0] + st.k[1] * st.d[1] + st.k[2] * st.d[2] + st.k[3] * st.d[3] + st.k[4] * self.channel_delta;
        let pred = (pred >> 3) & 0xff;
        let byte = (pred as u8).wrapping_sub(delta);
        let d = (delta as i8 as i32) << 3;
        let cd = self.channel_delta;
        let (d1, d2, d3, d4) = (st.d[0], st.d[1], st.d[2], st.d[3]);
        for (slot, v) in [d, d - d1, d + d1, d - d2, d + d2, d - d3, d + d3, d - d4, d + d4, d - cd, d + cd].into_iter().enumerate() {
            st.dif[slot] = st.dif[slot].wrapping_add(v.unsigned_abs());
        }
        self.channel_delta = byte.wrapping_sub(st.last_char as u8) as i8 as i32;
        st.last_delta = self.channel_delta;
        st.last_char = i32::from(byte);
        if st.count & 0x1f == 0 {
            let mut min = st.dif[0];
            let mut mi = 0;
            st.dif[0] = 0;
            for j in 1..11 {
                if st.dif[j] < min {
                    min = st.dif[j];
                    mi = j;
                }
                st.dif[j] = 0;
            }
            if mi > 0 {
                let k = &mut st.k[(mi - 1) / 2];
                if mi % 2 == 1 {
                    if *k >= -16 {
                        *k -= 1;
                    }
                } else if *k < 16 {
                    *k += 1;
                }
            }
        }
        byte
    }

    fn push_old(&mut self, d: usize) {
        self.old = [d, self.old[0], self.old[1], self.old[2]];
    }

    fn copy(&mut self, win: &mut Win, len: usize, dist: usize, limit: u64) -> Result<()> {
        let dist = dist.max(1);
        if len as u64 > limit - win.pos {
            return Err(Error::Corrupt("bad match"));
        }
        if dist as u64 > win.pos {
            // reaches before the start of the data: the window held zeros there
            for _ in 0..len {
                win.put(0);
            }
            return Ok(());
        }
        if !win.copy(dist, len) {
            return Err(Error::Corrupt("bad match"));
        }
        Ok(())
    }

    fn run_lz(&mut self, win: &mut Win, inp: &mut Input, end: u64, limit: u64) -> Result<()> {
        while win.pos < end {
            inp.need()?;
            let sym = self.main.decode(inp);
            if sym < 256 {
                win.put(sym as u8);
                continue;
            }
            match sym {
                256 => {
                    if self.last_len != 0 {
                        let (l, d) = (self.last_len, self.last_dist);
                        self.push_old(d);
                        self.copy(win, l, d, limit)?;
                    }
                }
                257..=260 => {
                    let dist = self.old[(sym - 257) as usize];
                    let slot = self.lens.decode(inp) as usize;
                    if slot >= LENS {
                        return Err(Error::Corrupt("bad length code"));
                    }
                    let mut len = LBASE[slot] as usize + 2;
                    if LBITS[slot] != 0 {
                        len += inp.bits(LBITS[slot] as u32) as usize;
                    }
                    if dist >= 0x101 {
                        len += 1;
                    }
                    if dist >= 0x2000 {
                        len += 1;
                    }
                    if dist >= 0x40000 {
                        len += 1;
                    }
                    self.push_old(dist);
                    self.last_dist = dist;
                    self.last_len = len;
                    self.copy(win, len, dist, limit)?;
                }
                261..=268 => {
                    let i = (sym - 261) as usize;
                    let dist = SBASE[i] as usize + 1 + inp.bits(SBITS[i] as u32) as usize;
                    self.push_old(dist);
                    self.last_dist = dist;
                    self.last_len = 2;
                    self.copy(win, 2, dist, limit)?;
                }
                269 => {
                    self.in_block = false;
                    return Ok(());
                }
                270..=297 => {
                    let slot = (sym - 270) as usize;
                    let mut len = LBASE[slot] as usize + 3;
                    if LBITS[slot] != 0 {
                        len += inp.bits(LBITS[slot] as u32) as usize;
                    }
                    let os = self.offs.decode(inp) as usize;
                    if os >= OFFS {
                        return Err(Error::Corrupt("bad offset code"));
                    }
                    let mut dist = OBASE[os] as usize + 1;
                    if OBITS[os] != 0 {
                        dist += inp.bits(OBITS[os] as u32) as usize;
                    }
                    if dist >= 0x2000 {
                        len += 1;
                    }
                    if dist >= 0x40000 {
                        len += 1;
                    }
                    self.push_old(dist);
                    self.last_dist = dist;
                    self.last_len = len;
                    self.copy(win, len, dist, limit)?;
                }
                _ => return Err(Error::Corrupt("bad symbol")),
            }
        }
        Ok(())
    }
}

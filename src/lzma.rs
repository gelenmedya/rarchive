//! LZMA and LZMA2 decoding, written for speed: the range coder lives in locals during a
//! run, input comes from a zero-padded buffer so symbols need no bounds checks, and output
//! goes straight into a ring window.
//!
//! Written from the LZMA algorithm as Igor Pavlov describes it in the public-domain LZMA SDK
//! documentation (lzma-specification.txt): probability models, state machine, length and
//! distance coding, end marker; and the LZMA2 chunk format (control byte, sizes, resets).

use std::io::{self, Read};

const PROB_INIT: u16 = 1024;
const NUM_STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const LEN_TO_POS_STATES: usize = 4;
const END_POS_MODEL: usize = 14;
const FULL_DISTANCES: usize = 128;
const ALIGN_BITS: u32 = 4;
const MATCH_MIN: usize = 2;
/// Input bytes a single symbol can consume at most (with margin).
const SYMBOL_MAX_IN: usize = 64;
/// Zero padding after the input, so reads past the end are harmless.
const IN_PAD: usize = 160;
/// Bytes past the ring end a fast match copy may write.
const WIN_SLACK: usize = 288;

#[derive(Clone)]
struct LenCoder {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES_MAX],
    mid: [[u16; 8]; POS_STATES_MAX],
    high: [u16; 256],
}

impl LenCoder {
    fn new() -> Self {
        LenCoder { choice: PROB_INIT, choice2: PROB_INIT, low: [[PROB_INIT; 8]; POS_STATES_MAX], mid: [[PROB_INIT; 8]; POS_STATES_MAX], high: [PROB_INIT; 256] }
    }
}

/// Probability models and coder state (everything a "state reset" resets).
#[derive(Clone)]
struct Model {
    is_match: [u16; NUM_STATES * POS_STATES_MAX],
    is_rep: [u16; NUM_STATES],
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [u16; NUM_STATES * POS_STATES_MAX],
    pos_slot: [[u16; 64]; LEN_TO_POS_STATES],
    spec_pos: [u16; 1 + FULL_DISTANCES - END_POS_MODEL],
    align: [u16; 1 << ALIGN_BITS],
    len: LenCoder,
    rep_len: LenCoder,
    literal: Vec<u16>,
}

/// Properties: literal context bits, literal position bits, position bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Props {
    pub(crate) fn from_byte(d: u8) -> Option<Props> {
        if d >= 9 * 5 * 5 {
            return None;
        }
        let d = d as u32;
        Some(Props { lc: d % 9, lp: (d / 9) % 5, pb: d / 45 })
    }
}

/// The LZMA decoder proper: window, models, state. Feeds on whole buffers of input.
pub(crate) struct Decoder {
    props: Props,
    m: Box<Model>,
    state: usize,
    reps: [u32; 4],
    win: Vec<u8>,
    /// ring size (`win.len() - WIN_SLACK`)
    wsize: usize,
    wpos: usize,
    /// bytes decoded since the last dictionary reset (match distances must stay below)
    total: u64,
    /// a match cut short by an output limit
    pending: usize,
    range: u32,
    code: u32,
}

#[derive(Debug)]
pub(crate) enum Stop {
    /// produced what was asked
    Limit,
    /// end marker seen
    End,
    /// the input buffer runs low (only when the caller has more input)
    Input,
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bad LZMA data")
}

impl Decoder {
    /// A decoder with a window of `dict` bytes (at least 4 KB), plus room for one LZMA2
    /// chunk of output that hasn't been read yet.
    pub(crate) fn new(props: Props, dict: u32) -> Decoder {
        let wsize = (dict as usize).max(4096) + (2 << 20) + 4096;
        let mut d = Decoder {
            props,
            m: Box::new(Model {
                is_match: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
                is_rep: [PROB_INIT; NUM_STATES],
                is_rep_g0: [PROB_INIT; NUM_STATES],
                is_rep_g1: [PROB_INIT; NUM_STATES],
                is_rep_g2: [PROB_INIT; NUM_STATES],
                is_rep0_long: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
                pos_slot: [[PROB_INIT; 64]; LEN_TO_POS_STATES],
                spec_pos: [PROB_INIT; 1 + FULL_DISTANCES - END_POS_MODEL],
                align: [PROB_INIT; 1 << ALIGN_BITS],
                len: LenCoder::new(),
                rep_len: LenCoder::new(),
                literal: Vec::new(),
            }),
            state: 0,
            reps: [0; 4],
            win: vec![0u8; wsize + WIN_SLACK],
            wsize,
            wpos: 0,
            total: 0,
            pending: 0,
            range: 0,
            code: 0,
        };
        d.reset_state(props);
        d
    }

    pub(crate) fn reset_dict(&mut self) {
        self.total = 0;
        self.pending = 0;
    }

    pub(crate) fn reset_state(&mut self, props: Props) {
        self.props = props;
        let m = &mut *self.m;
        let lit = 0x300usize << (props.lc + props.lp);
        m.literal.clear();
        m.literal.resize(lit, PROB_INIT);
        m.is_match.fill(PROB_INIT);
        m.is_rep.fill(PROB_INIT);
        m.is_rep_g0.fill(PROB_INIT);
        m.is_rep_g1.fill(PROB_INIT);
        m.is_rep_g2.fill(PROB_INIT);
        m.is_rep0_long.fill(PROB_INIT);
        for p in &mut m.pos_slot {
            p.fill(PROB_INIT);
        }
        m.spec_pos.fill(PROB_INIT);
        m.align.fill(PROB_INIT);
        m.len = LenCoder::new();
        m.rep_len = LenCoder::new();
        self.state = 0;
        self.reps = [0; 4];
        self.pending = 0;
    }

    /// Starts the range coder on `input` (5 bytes); returns bytes used.
    pub(crate) fn init_range(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() < 5 || input[0] != 0 {
            return Err(bad());
        }
        self.range = u32::MAX;
        self.code = u32::from_be_bytes(input[1..5].try_into().unwrap());
        Ok(5)
    }

    /// Ring index range of the last `n` bytes written (may wrap: two slices).
    pub(crate) fn recent(&self, n: usize) -> (&[u8], &[u8]) {
        let start = (self.wpos + self.wsize - n) % self.wsize;
        if start + n <= self.wsize {
            (&self.win[start..start + n], &[])
        } else {
            (&self.win[start..self.wsize], &self.win[..n - (self.wsize - start)])
        }
    }

    /// Copies `data` into the window as decoded output (LZMA2 uncompressed chunks).
    pub(crate) fn put_raw(&mut self, data: &[u8]) {
        for &b in data {
            self.win[self.wpos] = b;
            self.wpos += 1;
            if self.wpos == self.wsize {
                self.wpos = 0;
            }
        }
        self.total += data.len() as u64;
    }

    /// Decodes until `limit` bytes are produced or the end marker. `input` must be followed
    /// by at least IN_PAD readable bytes (zeros past the real data); `*ip` advances.
    /// `in_end`: where real input ends; reading beyond it is an error unless the output
    /// limit is reached first.
    /// `in_final`: `input` holds all the input there is (else decoding pauses with
    /// [`Stop::Input`] when fewer than a symbol's worth of bytes remain).
    pub(crate) fn decode(&mut self, input: &[u8], ip: &mut usize, in_end: usize, in_final: bool, limit: usize) -> io::Result<(usize, Stop)> {
        assert!(input.len() >= in_end + IN_PAD && *ip <= in_end + SYMBOL_MAX_IN);
        let mut out = 0usize;
        // a match cut short last time
        if self.pending > 0 {
            let n = self.pending.min(limit);
            self.copy_match(self.reps[0] as usize + 1, n);
            self.pending -= n;
            out += n;
        }
        let pb_mask = (1u64 << self.props.pb) - 1;
        let lp_mask = (1u64 << self.props.lp) - 1;
        let lc = self.props.lc;
        let mut range = self.range;
        let mut code = self.code;
        let mut i = *ip;
        let mut state = self.state;
        let m = &mut *self.m;

        macro_rules! norm {
            () => {
                if range < (1 << 24) {
                    range <<= 8;
                    debug_assert!(i < input.len());
                    // SAFETY: decoding stops once i passes in_end + SYMBOL_MAX_IN, one symbol
                    // reads at most SYMBOL_MAX_IN more bytes, and callers guarantee
                    // input.len() >= in_end + IN_PAD (> in_end + 2 * SYMBOL_MAX_IN)
                    code = (code << 8) | unsafe { *input.get_unchecked(i) } as u32;
                    i += 1;
                }
            };
        }
        // Branch-free: LZMA's bits are close to coin flips for the branch predictor.
        // Bit 0: range = bound, p += (2048 - p) >> 5. Bit 1: range -= bound, code -= bound,
        // p -= p >> 5. Both prob updates are p - ((p + offset) >> 5) in wrapping u32 maths,
        // with offset 31 - 2048 for bit 0 and 0 for bit 1.
        macro_rules! bit {
            ($p:expr) => {{
                let p = &mut $p;
                norm!();
                let pv = *p as u32;
                let bound = (range >> 11) * pv;
                let mask = 0u32.wrapping_sub((code >= bound) as u32);
                range = (bound & !mask) | (range.wrapping_sub(bound) & mask);
                code = code.wrapping_sub(bound & mask);
                let offset = 0xFFFF_F81Fu32 & !mask;
                *p = pv.wrapping_sub(pv.wrapping_add(offset) >> 5) as u16;
                mask & 1
            }};
        }
        macro_rules! tree {
            ($probs:expr, $bits:expr) => {{
                let probs = &mut $probs;
                let mut s = 1usize;
                for _ in 0..$bits {
                    s = (s << 1) | bit!(probs[s]) as usize;
                }
                s - (1 << $bits)
            }};
        }
        macro_rules! len {
            ($lc:expr, $ps:expr) => {{
                let l = &mut $lc;
                if bit!(l.choice) == 0 {
                    tree!(l.low[$ps], 3)
                } else if bit!(l.choice2) == 0 {
                    8 + tree!(l.mid[$ps], 3)
                } else {
                    16 + tree!(l.high, 8)
                }
            }};
        }

        // window state in locals for the hot loop
        let w = self.wsize;
        let win = &mut self.win[..];
        let mut wp = self.wpos;
        let base = self.total;
        let mut reps = self.reps;
        let mut pending = 0usize;
        // position `d` bytes back (1 <= d <= w)
        macro_rules! back {
            ($d:expr) => {{
                let d = $d;
                if wp >= d { wp - d } else { wp + w - d }
            }};
        }
        let res: io::Result<Stop> = loop {
            if out >= limit {
                break Ok(Stop::Limit);
            }
            if !in_final && i + SYMBOL_MAX_IN > in_end {
                break Ok(Stop::Input);
            }
            if i > in_end + SYMBOL_MAX_IN {
                break Err(bad()); // ran far past the input: damaged
            }
            let pos = base + out as u64;
            let ps = (pos & pb_mask) as usize;
            if bit!(m.is_match[(state << 4) + ps]) == 0 {
                // literal
                let prev = if pos > 0 { win[back!(1)] } else { 0 };
                let lit = 0x300 * ((((pos & lp_mask) << lc) as usize) + ((prev as usize) >> (8 - lc)));
                let probs = &mut m.literal[lit..lit + 0x300];
                let mut s = 1usize;
                if state >= 7 {
                    // a "matched" literal: guided by the byte at rep0 until they differ
                    let mut mb = win[back!(reps[0] as usize + 1)] as usize;
                    loop {
                        let mbit = (mb >> 7) & 1;
                        mb <<= 1;
                        let b = bit!(probs[0x100 + (mbit << 8) + s]) as usize;
                        s = (s << 1) | b;
                        if mbit != b || s >= 0x100 {
                            break;
                        }
                    }
                }
                while s < 0x100 {
                    s = (s << 1) | bit!(probs[s]) as usize;
                }
                win[wp] = s as u8;
                wp += 1;
                if wp == w {
                    wp = 0;
                }
                out += 1;
                state = if state < 4 {
                    0
                } else if state < 10 {
                    state - 3
                } else {
                    state - 6
                };
                continue;
            }
            let len;
            if bit!(m.is_rep[state]) == 0 {
                // a new match
                len = len!(m.len, ps);
                state = if state < 7 { 7 } else { 10 };
                let lps = len.min(LEN_TO_POS_STATES - 1);
                let slot = tree!(m.pos_slot[lps], 6) as u32;
                let dist = if slot < 4 {
                    slot
                } else {
                    let nb = (slot >> 1) - 1;
                    let mut d = (2 | (slot & 1)) << nb;
                    if (slot as usize) < END_POS_MODEL {
                        // reverse bit tree over spec_pos
                        let sp = d as usize - slot as usize;
                        let mut t = 1usize;
                        for k in 0..nb {
                            let b = bit!(m.spec_pos[sp + t]);
                            t = (t << 1) | b as usize;
                            d |= b << k;
                        }
                        d
                    } else {
                        // direct bits, then 4 align bits in reverse
                        let mut v = 0u32;
                        for _ in 0..nb - ALIGN_BITS {
                            norm!();
                            range >>= 1;
                            let t = code.wrapping_sub(range) >> 31; // 1 when code < range
                            code = code.wrapping_sub(range & t.wrapping_sub(1));
                            v = (v << 1) | (1 - t);
                        }
                        d = d.wrapping_add(v << ALIGN_BITS);
                        let mut t = 1usize;
                        for k in 0..ALIGN_BITS {
                            let b = bit!(m.align[t]);
                            t = (t << 1) | b as usize;
                            d |= b << k;
                        }
                        d
                    }
                };
                if dist == u32::MAX {
                    break Ok(Stop::End);
                }
                reps = [dist, reps[0], reps[1], reps[2]];
            } else if bit!(m.is_rep_g0[state]) == 0 {
                if bit!(m.is_rep0_long[(state << 4) + ps]) == 0 {
                    // short rep: one byte at rep0
                    let d = reps[0] as usize + 1;
                    if pos == 0 || d > w {
                        break Err(bad());
                    }
                    state = if state < 7 { 9 } else { 11 };
                    win[wp] = win[back!(d)];
                    wp += 1;
                    if wp == w {
                        wp = 0;
                    }
                    out += 1;
                    continue;
                }
                len = len!(m.rep_len, ps);
                state = if state < 7 { 8 } else { 11 };
            } else {
                let dist;
                if bit!(m.is_rep_g1[state]) == 0 {
                    dist = reps[1];
                } else {
                    if bit!(m.is_rep_g2[state]) == 0 {
                        dist = reps[2];
                    } else {
                        dist = reps[3];
                        reps[3] = reps[2];
                    }
                    reps[2] = reps[1];
                }
                reps[1] = reps[0];
                reps[0] = dist;
                len = len!(m.rep_len, ps);
                state = if state < 7 { 8 } else { 11 };
            }
            let len = len + MATCH_MIN;
            let d = reps[0] as usize + 1;
            if d as u64 > pos || d > w {
                break Err(bad());
            }
            let n = len.min(limit - out);
            copy_match(win, &mut wp, w, d, n);
            out += n;
            pending = len - n;
        };
        self.wpos = wp;
        self.reps = reps;
        self.pending += pending;
        self.range = range;
        self.code = code;
        self.state = state;
        *ip = i;
        self.total += out as u64;
        res.map(|s| (out, s))
    }

    fn copy_match(&mut self, d: usize, n: usize) {
        copy_match(&mut self.win, &mut self.wpos, self.wsize, d, n);
    }
}

/// Copies `n` bytes from `d` back in the ring window `win[..w]` at `*wpos`.
#[inline(always)]
fn copy_match(win: &mut [u8], wpos: &mut usize, w: usize, d: usize, n: usize) {
    let src = if *wpos >= d { *wpos - d } else { *wpos + w - d };
    // common case: no wrap on either side, room for 16-byte over-copies in the slack
    if src + n + 16 <= win.len() && *wpos + n + 16 <= win.len() && *wpos + n <= w && src + n <= w {
        let p = win.as_mut_ptr();
        // SAFETY: both ranges plus 16 bytes are inside `win` (checked above); with d >= 16
        // each 16-byte step reads only bytes already final, and bytes written past the
        // match end are future output overwritten before use
        unsafe {
            if d >= 16 {
                let mut k = 0;
                while k < n {
                    let v = std::ptr::read_unaligned(p.add(src + k) as *const [u8; 16]);
                    std::ptr::write_unaligned(p.add(*wpos + k) as *mut [u8; 16], v);
                    k += 16;
                }
            } else {
                for k in 0..n {
                    *p.add(*wpos + k) = *p.add(src + k);
                }
            }
        }
        *wpos += n;
        if *wpos == w {
            *wpos = 0;
        }
        return;
    }
    {
        if src + n <= w && *wpos + n <= w && (d >= 16 || n <= d) {
            if d >= n {
                win.copy_within(src..src + n, *wpos);
            } else {
                // overlapping with d >= 16: 16-byte steps never read unwritten bytes
                let mut k = 0;
                while k < n {
                    let c = (n - k).min(16);
                    win.copy_within(src + k..src + k + c, *wpos + k);
                    k += c;
                }
            }
            *wpos += n;
            if *wpos == w {
                *wpos = 0;
            }
            return;
        }
        let mut s = src;
        for _ in 0..n {
            win[*wpos] = win[s];
            *wpos += 1;
            if *wpos == w {
                *wpos = 0;
            }
            s += 1;
            if s == w {
                s = 0;
            }
        }
    }
}

/// LZMA2 stream reader.
pub(crate) struct Lzma2Reader<R> {
    inner: R,
    dec: Decoder,
    /// current chunk's packed bytes (+ padding)
    buf: Vec<u8>,
    /// output of the current chunk not yet handed out
    avail: usize,
    /// LZMA chunk being decoded: input position and end, output still to produce
    ip: usize,
    in_end: usize,
    chunk_left: usize,
    done: bool,
    need_props: bool,
}

impl<R: Read> Lzma2Reader<R> {
    pub(crate) fn new(inner: R, dict: u32) -> Self {
        Lzma2Reader {
            inner,
            dec: Decoder::new(Props { lc: 0, lp: 0, pb: 0 }, dict),
            buf: Vec::new(),
            avail: 0,
            ip: 0,
            in_end: 0,
            chunk_left: 0,
            done: false,
            need_props: true,
        }
    }

    /// Reads the next chunk header and its data; false at the end of the stream.
    fn next_chunk(&mut self) -> io::Result<bool> {
        let mut c = [0u8; 1];
        if self.inner.read(&mut c)? == 0 {
            return Ok(false); // tolerate a missing end byte
        }
        let c = c[0];
        if c == 0 {
            return Ok(false);
        }
        if c == 1 || c == 2 {
            let mut h = [0u8; 2];
            self.inner.read_exact(&mut h)?;
            let n = u16::from_be_bytes(h) as usize + 1;
            if c == 1 {
                self.dec.reset_dict();
            }
            self.buf.clear();
            self.buf.resize(n, 0);
            self.inner.read_exact(&mut self.buf)?;
            let data = std::mem::take(&mut self.buf);
            self.dec.put_raw(&data);
            self.buf = data;
            self.avail = n;
            return Ok(true);
        }
        if c < 0x80 {
            return Err(bad());
        }
        let mut h = [0u8; 4];
        self.inner.read_exact(&mut h)?;
        let unpacked = (((c & 0x1F) as usize) << 16 | u16::from_be_bytes([h[0], h[1]]) as usize) + 1;
        let packed = u16::from_be_bytes([h[2], h[3]]) as usize + 1;
        let mode = (c >> 5) & 3;
        if mode == 3 {
            self.dec.reset_dict();
        }
        if mode >= 2 {
            let mut p = [0u8; 1];
            self.inner.read_exact(&mut p)?;
            let props = Props::from_byte(p[0]).filter(|p| p.lc + p.lp <= 4).ok_or_else(bad)?;
            self.dec.reset_state(props);
            self.need_props = false;
        } else if self.need_props {
            return Err(bad());
        } else if mode == 1 {
            let props = self.dec.props;
            self.dec.reset_state(props);
        }
        self.buf.clear();
        self.buf.resize(packed + IN_PAD, 0);
        self.inner.read_exact(&mut self.buf[..packed])?;
        self.ip = self.dec.init_range(&self.buf)?;
        self.in_end = packed;
        self.chunk_left = unpacked;
        Ok(true)
    }
}

impl<R: Read> Read for Lzma2Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.avail > 0 {
                let n = out.len().min(self.avail);
                let (a, b) = self.dec.recent(self.avail);
                let k = n.min(a.len());
                out[..k].copy_from_slice(&a[..k]);
                if n > k {
                    out[k..n].copy_from_slice(&b[..n - k]);
                }
                self.avail -= n;
                return Ok(n);
            }
            if self.chunk_left > 0 {
                // decode up to 256 KB of this chunk, then hand it out
                let step = self.chunk_left.min(256 << 10);
                let (n, stop) = self.dec.decode(&self.buf, &mut self.ip, self.in_end, true, step)?;
                if n == 0 || matches!(stop, Stop::End) && n < step {
                    return Err(bad()); // LZMA2 chunks have no end markers
                }
                self.chunk_left -= n;
                self.avail = n;
                continue;
            }
            if self.done {
                return Ok(0);
            }
            if !self.next_chunk()? {
                self.done = true;
                return Ok(0);
            }
        }
    }
}

/// LZMA (".lzma" / 7z / zip LZMA) stream reader with a known output size; the input is read
/// in large blocks.
pub(crate) struct LzmaReader<R> {
    inner: R,
    dec: Decoder,
    buf: Vec<u8>,
    ip: usize,
    /// real bytes in `buf`
    len: usize,
    eof: bool,
    left: u64,
    avail: usize,
    started: bool,
    /// the decoder paused for input: read more even above the low-water mark
    refill_now: bool,
}

impl<R: Read> LzmaReader<R> {
    pub(crate) fn new(inner: R, props: u8, dict: u32, size: u64) -> io::Result<Self> {
        let props = Props::from_byte(props).ok_or_else(bad)?;
        Ok(LzmaReader { inner, dec: Decoder::new(props, dict), buf: vec![0; (1 << 20) + IN_PAD], ip: 0, len: 0, eof: false, left: size, avail: 0, started: false, refill_now: false })
    }

    /// Keeps at least SYMBOL_MAX_IN bytes ahead of `ip` unless the input is exhausted.
    fn refill(&mut self) -> io::Result<()> {
        if self.eof || (!self.refill_now && self.len - self.ip >= SYMBOL_MAX_IN * 64) {
            return Ok(());
        }
        self.refill_now = false;
        self.buf.copy_within(self.ip..self.len, 0);
        self.len -= self.ip;
        self.ip = 0;
        let cap = self.buf.len() - IN_PAD;
        while self.len < cap {
            let n = self.inner.read(&mut self.buf[self.len..cap])?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.len += n;
        }
        self.buf[self.len..].fill(0);
        Ok(())
    }
}

impl<R: Read> Read for LzmaReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.avail > 0 {
                let n = out.len().min(self.avail);
                let (a, b) = self.dec.recent(self.avail);
                let k = n.min(a.len());
                out[..k].copy_from_slice(&a[..k]);
                if n > k {
                    out[k..n].copy_from_slice(&b[..n - k]);
                }
                self.avail -= n;
                return Ok(n);
            }
            if self.left == 0 {
                return Ok(0);
            }
            self.refill()?;
            if !self.started {
                self.ip = self.dec.init_range(&self.buf[..self.len.max(5)])?;
                self.started = true;
            }
            // decode while enough input is buffered (or all of it is)
            let step = self.left.min(256 << 10) as usize;
            let in_end = self.len;
            let (n, stop) = self.dec.decode(&self.buf, &mut self.ip, in_end, self.eof, step)?;
            self.left -= n as u64;
            self.avail = n;
            match stop {
                Stop::End => self.left = 0,
                Stop::Input if n == 0 && self.eof => return Err(bad()),
                Stop::Input => self.refill_now = true,
                Stop::Limit if n == 0 && self.left > 0 => return Err(bad()),
                Stop::Limit => {}
            }
        }
    }
}

//! PPMd variant H (Dmitry Shkarin's PPMd var.H) as RAR 3.x / 4.x uses it: the context model
//! with its sub-allocator and the carry-less range decoder.
//!
//! Provenance: written for rarchive from Shkarin's public description of PPMd var.H (the model:
//! binary contexts, SEE, rescale, successor creation; the sub-allocator with 12-byte units,
//! 38 free lists and block gluing) and checked against the `rars` crate's `codec/ppmd.rs`
//! (Apache-2.0), whose notes on what has to match the reference allocator bit for bit
//! (restart timing, free-list order, the 16-bit unit counter in glued runs) were followed.
//! The model lives in one byte arena addressed by 32-bit offsets, like the reference.
//! Damaged data cannot make it leave the arena: every symbol sequence is a legal model
//! evolution, and offsets are bounds-checked.

use super::bitio::Input;
use crate::error::{Error, Result};

const MAX_FREQ: u32 = 124;
const UNIT_SIZE: u32 = 12;
const N_INDEXES: usize = 38;
const MAX_ORDER: usize = 64;
const BIN_SCALE: u32 = 1 << 14;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;
const INIT_BIN_ESC: [u16; 8] = [0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
/// Largest model memory a RAR stream can ask for (the size byte plus one, in MB).
pub(super) const MAX_MEMORY: usize = 256 << 20;
/// The arena of a model that holds nothing yet (so accessors are always in bounds).
const SPARE: usize = 64;

#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

pub(super) struct Ppmd {
    mem: Vec<u8>,
    /// Highest offset an access may start at (`mem.len() - 8`).
    max_off: usize,
    size: u32,
    align: u32,
    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; N_INDEXES],
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    bin_summ: Box<[[u16; 64]; 128]>,
    see: [[See; 16]; 25],
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    // range decoder
    range: u32,
    code: u32,
    low: u32,
    ready: bool,
}

impl Ppmd {
    pub(super) fn new() -> Ppmd {
        let mut indx2units = [0u8; N_INDEXES];
        let mut units2indx = [0u8; 128];
        let mut k = 0usize;
        for i in 0..N_INDEXES {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                units2indx[k] = i as u8;
                k += 1;
            }
            indx2units[i] = k as u8;
        }
        let mut ns2bsindx = [6u8; 256];
        ns2bsindx[0] = 0;
        ns2bsindx[1] = 2;
        ns2bsindx[2..11].fill(4);
        let mut ns2indx = [0u8; 256];
        for (i, v) in ns2indx.iter_mut().enumerate().take(3) {
            *v = i as u8;
        }
        let (mut m, mut k) = (3u32, 1u32);
        for v in ns2indx.iter_mut().skip(3) {
            *v = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }
        let mut hb2flag = [0u8; 256];
        hb2flag[0x40..].fill(8);
        Ppmd {
            mem: vec![0u8; SPARE],
            max_off: SPARE - 8,
            size: 0,
            align: 0,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; N_INDEXES],
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            bin_summ: Box::new([[0; 64]; 128]),
            see: [[See::default(); 16]; 25],
            indx2units,
            units2indx,
            ns2indx,
            ns2bsindx,
            hb2flag,
            range: 0,
            code: 0,
            low: 0,
            ready: false,
        }
    }

    /// Bytes of model memory currently held.
    pub(super) fn memory(&self) -> usize {
        self.size as usize
    }

    /// Frees the model memory.
    pub(super) fn release(&mut self) {
        self.mem = vec![0u8; SPARE];
        self.max_off = SPARE - 8;
        self.size = 0;
        self.ready = false;
    }

    // ---- arena access ----
    //
    // Offsets come from the model itself, never from the stream, so they stay inside the
    // arena; as a last line of defence every access clamps its offset to the last 8 readable
    // bytes (a compare and a select, no branch, no panic path): a model bug could then read or
    // write wrong data, never outside the arena.

    #[inline(always)]
    fn at(&self, o: u32) -> usize {
        (o as usize).min(self.max_off)
    }
    #[inline(always)]
    fn r8(&self, o: u32) -> u8 {
        // SAFETY (this and the accessors below): at() <= len - 8, so the widest access
        // (4 bytes) stays inside `mem`
        unsafe { *self.mem.as_ptr().add(self.at(o)) }
    }
    #[inline(always)]
    fn r16(&self, o: u32) -> u16 {
        u16::from_le(unsafe { self.mem.as_ptr().add(self.at(o)).cast::<u16>().read_unaligned() })
    }
    #[inline(always)]
    fn r32(&self, o: u32) -> u32 {
        u32::from_le(unsafe { self.mem.as_ptr().add(self.at(o)).cast::<u32>().read_unaligned() })
    }
    #[inline(always)]
    fn w8(&mut self, o: u32, v: u8) {
        let i = self.at(o);
        unsafe { *self.mem.as_mut_ptr().add(i) = v }
    }
    #[inline(always)]
    fn w16(&mut self, o: u32, v: u16) {
        let i = self.at(o);
        unsafe { self.mem.as_mut_ptr().add(i).cast::<u16>().write_unaligned(v.to_le()) }
    }
    #[inline(always)]
    fn w32(&mut self, o: u32, v: u32) {
        let i = self.at(o);
        unsafe { self.mem.as_mut_ptr().add(i).cast::<u32>().write_unaligned(v.to_le()) }
    }

    // context: NumStats u16 @0, SummFreq u16 @2, Stats u32 @4, Suffix u32 @8; a context with one
    // symbol keeps that state inline at @2.
    #[inline(always)]
    fn ns(&self, c: u32) -> u32 {
        u32::from(self.r16(c))
    }
    #[inline(always)]
    fn summ(&self, c: u32) -> u32 {
        u32::from(self.r16(c + 2))
    }
    #[inline(always)]
    fn stats(&self, c: u32) -> u32 {
        self.r32(c + 4)
    }
    #[inline(always)]
    fn suffix(&self, c: u32) -> u32 {
        self.r32(c + 8)
    }
    // state (6 bytes): Symbol u8 @0, Freq u8 @1, Successor u32 @2
    #[inline(always)]
    fn sym(&self, s: u32) -> u8 {
        self.r8(s)
    }
    #[inline(always)]
    fn freq(&self, s: u32) -> u32 {
        u32::from(self.r8(s + 1))
    }
    #[inline(always)]
    fn succ(&self, s: u32) -> u32 {
        self.r32(s + 2)
    }
    #[inline(always)]
    fn set_freq(&mut self, s: u32, f: u32) {
        self.w8(s + 1, f as u8);
    }
    #[inline(always)]
    fn set_succ(&mut self, s: u32, v: u32) {
        self.w32(s + 2, v);
    }
    fn copy_state(&mut self, dst: u32, src: u32) {
        let (d, s) = (dst as usize, src as usize);
        self.mem.copy_within(s..s + 6, d);
    }
    fn read_state(&self, s: u32) -> [u8; 6] {
        self.mem[s as usize..s as usize + 6].try_into().unwrap()
    }
    fn write_state(&mut self, s: u32, v: [u8; 6]) {
        self.mem[s as usize..s as usize + 6].copy_from_slice(&v);
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        let (x, y) = (self.read_state(a), self.read_state(b));
        self.write_state(a, y);
        self.write_state(b, x);
    }

    // ---- sub-allocator ----

    #[inline(always)]
    fn u2b(nu: u32) -> u32 {
        nu * UNIT_SIZE
    }
    #[inline(always)]
    fn u2i(&self, nu: u32) -> usize {
        self.units2indx[nu as usize - 1] as usize
    }
    #[inline(always)]
    fn i2u(&self, i: usize) -> u32 {
        u32::from(self.indx2units[i])
    }

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head = self.free_list[indx];
        self.w32(node, head);
        self.free_list[indx] = node;
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.r32(node);
        node
    }

    fn split_block(&mut self, ptr: u32, old_i: usize, new_i: usize) {
        let nu = self.i2u(old_i) - self.i2u(new_i);
        let ptr = ptr + Self::u2b(self.i2u(new_i));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + Self::u2b(k), (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    // Node layout while gluing: Stamp u16 @0 (0 = free), NU u16 @2, Next u32 @4, Prev u32 @8.
    fn glue_free_blocks(&mut self) {
        super::count(9);
        let head = self.align + self.size; // the spare unit past the arena
        let mut n = head;
        self.glue_count = 255;
        for i in 0..N_INDEXES {
            let nu = self.i2u(i) as u16;
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node = next;
                self.w32(node + 4, n); // node.next = n
                self.w32(n + 8, node); // n.prev = node
                n = node;
                next = self.r32(node);
                self.w16(node, 0);
                self.w16(node + 2, nu);
            }
        }
        self.w16(head, 1);
        self.w32(head + 4, n);
        self.w32(n + 8, head);
        if self.lo_unit != self.hi_unit {
            self.w16(self.lo_unit, 1);
        }
        // glue neighbours
        while n != head {
            let node = n;
            let mut nu = u32::from(self.r16(node + 2));
            loop {
                let node2 = node + nu * UNIT_SIZE;
                nu += u32::from(self.r16(node2 + 2));
                if self.r16(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                let (prev, next) = (self.r32(node2 + 8), self.r32(node2 + 4));
                self.w32(prev + 4, next);
                self.w32(next + 8, prev);
                self.w16(node + 2, nu as u16);
            }
            n = self.r32(node + 4);
        }
        // refill the free lists
        n = self.r32(head + 4);
        while n != head {
            let mut node = n;
            let next = self.r32(node + 4);
            let mut nu = u32::from(self.r16(node + 2));
            while nu > 128 {
                self.insert_node(node, N_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
            n = next;
        }
    }

    /// `None` when memory is exhausted (the model restarts).
    fn alloc_units_rare(&mut self, indx: usize) -> Option<u32> {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return Some(self.remove_node(indx));
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == N_INDEXES {
                let bytes = Self::u2b(self.i2u(indx));
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if self.units_start - self.text > bytes {
                    self.units_start -= bytes;
                    Some(self.units_start)
                } else {
                    None
                };
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        Some(block)
    }

    fn alloc_units(&mut self, indx: usize) -> Option<u32> {
        if self.free_list[indx] != 0 {
            return Some(self.remove_node(indx));
        }
        let bytes = Self::u2b(self.i2u(indx));
        if bytes <= self.hi_unit - self.lo_unit {
            let r = self.lo_unit;
            self.lo_unit += bytes;
            return Some(r);
        }
        self.alloc_units_rare(indx)
    }

    fn copy_units(&mut self, dst: u32, src: u32, nu: u32) {
        let n = (nu * UNIT_SIZE) as usize;
        self.mem.copy_within(src as usize..src as usize + n, dst as usize);
    }

    fn shrink_units(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let (i0, i1) = (self.u2i(old_nu), self.u2i(new_nu));
        if i0 == i1 {
            return old;
        }
        if self.free_list[i1] != 0 {
            let ptr = self.remove_node(i1);
            self.copy_units(ptr, old, new_nu);
            self.insert_node(old, i0);
            return ptr;
        }
        self.split_block(old, i0, i1);
        old
    }

    // ---- model ----

    fn restart_model(&mut self) {
        super::count(8);
        self.free_list = [0; N_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.units_start;
        self.glue_count = 0;
        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;
        self.hi_unit -= UNIT_SIZE;
        let ctx = self.hi_unit;
        self.min_context = ctx;
        self.max_context = ctx;
        self.w32(ctx + 8, 0); // suffix
        self.w16(ctx, 256);
        self.w16(ctx + 2, 256 + 1);
        self.found_state = self.lo_unit;
        self.w32(ctx + 4, self.lo_unit);
        for i in 0..256u32 {
            let s = self.lo_unit + i * 6;
            self.w8(s, i as u8);
            self.w8(s + 1, 1);
            self.w32(s + 2, 0);
        }
        self.lo_unit += Self::u2b(256 / 2);
        for i in 0..128usize {
            for k in 0..8usize {
                let val = (BIN_SCALE - u32::from(INIT_BIN_ESC[k]) / (i as u32 + 2)) as u16;
                for m in (0..64).step_by(8) {
                    self.bin_summ[i][k + m] = val;
                }
            }
        }
        for i in 0..25usize {
            for k in 0..16usize {
                self.see[i][k] = See { summ: ((5 * i as u32 + 10) << (PERIOD_BITS - 4)) as u16, shift: (PERIOD_BITS - 4) as u8, count: 4 };
            }
        }
    }

    fn create_successors(&mut self, skip: bool) -> Option<u32> {
        let mut c = self.min_context;
        let up_branch = self.succ(self.found_state);
        let fsym = self.sym(self.found_state);
        let mut ps = [0u32; MAX_ORDER];
        let mut num = 0usize;
        if !skip {
            ps[num] = self.found_state;
            num += 1;
        }
        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = if self.ns(c) != 1 {
                let mut s = self.stats(c);
                while self.sym(s) != fsym {
                    s += 6;
                }
                s
            } else {
                c + 2
            };
            let successor = self.succ(s);
            if successor != up_branch {
                c = successor;
                if num == 0 {
                    return Some(c);
                }
                break;
            }
            if num >= MAX_ORDER {
                return None;
            }
            ps[num] = s;
            num += 1;
        }
        let up_sym = self.r8(up_branch);
        let up_succ = up_branch + 1;
        let up_freq = if self.ns(c) == 1 {
            self.freq(c + 2)
        } else {
            let mut s = self.stats(c);
            while self.sym(s) != up_sym {
                s += 6;
            }
            let cf = self.freq(s) - 1;
            let s0 = self.summ(c) - self.ns(c) - cf;
            1 + if 2 * cf <= s0 { (5 * cf > s0) as u32 } else { (2 * cf + 3 * s0 - 1) / (2 * s0).max(1) }
        };
        loop {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                self.alloc_units_rare(0)?
            };
            self.w16(c1, 1);
            self.w8(c1 + 2, up_sym);
            self.w8(c1 + 3, up_freq as u8);
            self.w32(c1 + 4, up_succ);
            self.w32(c1 + 8, c);
            num -= 1;
            self.set_succ(ps[num], c1);
            c = c1;
            if num == 0 {
                break;
            }
        }
        Some(c)
    }

    fn update_model(&mut self) {
        let fs = self.found_state;
        let fsym = self.sym(fs);
        let ffreq = self.freq(fs);
        let mut f_successor = self.succ(fs);
        if ffreq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.ns(c) == 1 {
                let s = c + 2;
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s) + 1);
                }
            } else {
                let mut s = self.stats(c);
                if self.sym(s) != fsym {
                    loop {
                        s += 6;
                        if self.sym(s) == fsym {
                            break;
                        }
                    }
                    if self.freq(s) >= self.freq(s - 6) {
                        self.swap_states(s, s - 6);
                        s -= 6;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 2);
                    self.w16(c + 2, (self.summ(c) + 2) as u16);
                }
            }
        }
        if self.order_fall == 0 {
            match self.create_successors(true) {
                None => {
                    self.restart_model();
                    return;
                }
                Some(c) => {
                    self.min_context = c;
                    self.max_context = c;
                    self.set_succ(self.found_state, c);
                }
            }
            return;
        }
        self.w8(self.text, fsym);
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }
        if f_successor != 0 {
            if f_successor <= successor {
                match self.create_successors(false) {
                    None => {
                        self.restart_model();
                        return;
                    }
                    Some(cs) => f_successor = cs,
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.text -= 1;
                }
            }
        } else {
            self.set_succ(self.found_state, successor);
            f_successor = self.min_context;
        }
        let ns = self.ns(self.min_context);
        let ffreq = self.freq(self.found_state);
        let s0 = self.summ(self.min_context) - ns - (ffreq - 1);
        let mut c = self.max_context;
        while c != self.min_context {
            let ns1 = self.ns(c);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let Some(ptr) = self.alloc_units(i + 1) else {
                            self.restart_model();
                            return;
                        };
                        let old = self.stats(c);
                        self.copy_units(ptr, old, old_nu);
                        self.insert_node(old, i);
                        self.w32(c + 4, ptr);
                    }
                }
                let sf = self.summ(c);
                let add = (2 * ns1 < ns) as u32 + 2 * ((4 * ns1 <= ns) as u32 & (sf <= 8 * ns1) as u32);
                self.w16(c + 2, (sf + add) as u16);
            } else {
                let Some(s) = self.alloc_units(0) else {
                    self.restart_model();
                    return;
                };
                self.copy_state(s, c + 2);
                self.w32(c + 4, s);
                let f = self.freq(s);
                let nf = if f < MAX_FREQ / 4 - 1 { f << 1 } else { MAX_FREQ - 4 };
                self.set_freq(s, nf);
                self.w16(c + 2, (nf + self.init_esc + (ns > 3) as u32) as u16);
            }
            let sfq = self.summ(c);
            let mut cf = 2 * ffreq * (sfq + 6);
            let sf = s0 + sfq;
            if cf < 6 * sf {
                cf = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                self.w16(c + 2, (sfq + 3) as u16);
            } else {
                cf = 4 + (cf >= 9 * sf) as u32 + (cf >= 12 * sf) as u32 + (cf >= 15 * sf) as u32;
                self.w16(c + 2, (sfq + cf) as u16);
            }
            let s = self.stats(c) + ns1 * 6;
            self.set_succ(s, successor);
            self.w8(s, fsym);
            self.set_freq(s, cf);
            self.w16(c, (ns1 + 1) as u16);
            c = self.suffix(c);
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;
        if s != stats {
            let tmp = self.read_state(s);
            while s != stats {
                self.copy_state(s, s - 6);
                s -= 6;
            }
            self.write_state(s, tmp);
        }
        let mut esc_freq = self.summ(mc) - self.freq(s);
        let adder = (self.order_fall != 0) as u32;
        let f = (self.freq(s) + 4 + adder) >> 1;
        self.set_freq(s, f);
        let mut sum_freq = f;
        let mut i = self.ns(mc) - 1;
        while i > 0 {
            s += 6;
            esc_freq -= self.freq(s);
            let f = (self.freq(s) + adder) >> 1;
            self.set_freq(s, f);
            sum_freq += f;
            if f > self.freq(s - 6) {
                let tmp = self.read_state(s);
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1 - 6);
                    s1 -= 6;
                    if s1 == stats || u32::from(tmp[1]) <= self.freq(s1 - 6) {
                        break;
                    }
                }
                self.write_state(s1, tmp);
            }
            i -= 1;
        }
        if self.freq(s) == 0 {
            let num_stats = self.ns(mc);
            let mut i = 0u32;
            loop {
                i += 1;
                s -= 6;
                if self.freq(s) != 0 {
                    break;
                }
            }
            esc_freq += i;
            let new_ns = num_stats - i;
            self.w16(mc, new_ns as u16);
            if new_ns == 1 {
                let mut tmp = self.read_state(stats);
                let mut t = u32::from(tmp[1]);
                loop {
                    t -= t >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                tmp[1] = t as u8;
                let idx = self.u2i((num_stats + 1) >> 1);
                self.insert_node(stats, idx);
                self.found_state = mc + 2;
                self.write_state(mc + 2, tmp);
                return;
            }
            let n0 = (num_stats + 1) >> 1;
            let n1 = (new_ns + 1) >> 1;
            if n0 != n1 {
                let ns = self.shrink_units(stats, n0, n1);
                self.w32(mc + 4, ns);
            }
        }
        self.w16(mc + 2, (sum_freq + esc_freq - (esc_freq >> 1)) as u16);
        self.found_state = self.stats(mc);
    }

    /// The SEE context for an escape (`None` is the dummy one) and the escape frequency.
    fn make_esc_freq(&mut self, num_masked: u32) -> (Option<(usize, usize)>, u32) {
        let mc = self.min_context;
        let ns = self.ns(mc);
        if ns != 256 {
            let non_masked = ns - num_masked;
            let suffix_ns = self.ns(self.suffix(mc));
            let idx = (non_masked < suffix_ns.wrapping_sub(ns)) as usize
                + 2 * (self.summ(mc) < 11 * ns) as usize
                + 4 * (num_masked > non_masked) as usize
                + self.hi_bits_flag as usize;
            let row = self.ns2indx[(non_masked - 1) as usize] as usize;
            let see = &mut self.see[row][idx];
            let r = u32::from(see.summ >> see.shift);
            see.summ = see.summ.wrapping_sub(r as u16);
            (Some((row, idx)), r + (r == 0) as u32)
        } else {
            (None, 1)
        }
    }

    fn next_context(&mut self) {
        let c = self.succ(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s = self.found_state;
        self.set_freq(s, self.freq(s) + 4);
        let mc = self.min_context;
        self.w16(mc + 2, (self.summ(mc) + 4) as u16);
        if self.freq(s) > self.freq(s - 6) {
            self.swap_states(s, s - 6);
            s -= 6;
            self.found_state = s;
            if self.freq(s) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        self.prev_success = (2 * self.freq(s) > self.summ(mc)) as u32;
        self.run_length += self.prev_success as i32;
        self.w16(mc + 2, (self.summ(mc) + 4) as u16);
        let f = self.freq(s) + 4;
        self.set_freq(s, f);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let s = self.found_state;
        let f = self.freq(s);
        self.set_freq(s, f + (f < 128) as u32);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        self.w16(mc + 2, (self.summ(mc) + 4) as u16);
        let f = self.freq(s) + 4;
        self.set_freq(s, f);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    // ---- range decoder (the carry-less coder RAR uses) ----

    fn range_init(&mut self, inp: &mut Input) -> Result<()> {
        self.code = 0;
        self.low = 0;
        self.range = 0xffff_ffff;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(inp.byte()?);
        }
        if self.code == 0xffff_ffff {
            return Err(Error::Corrupt("PPMd range code"));
        }
        Ok(())
    }

    #[inline(always)]
    fn threshold(&mut self, total: u32) -> Result<u32> {
        if total == 0 {
            return Err(Error::Corrupt("PPMd range"));
        }
        self.range /= total;
        if self.range == 0 {
            return Err(Error::Corrupt("PPMd range"));
        }
        Ok(self.code.wrapping_sub(self.low) / self.range)
    }

    #[inline(always)]
    fn rc_decode(&mut self, start: u32, size: u32) {
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
    }

    #[inline(always)]
    fn normalize(&mut self, inp: &mut Input) -> Result<()> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return Ok(());
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.code = (self.code << 8) | u32::from(inp.byte()?);
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    /// Starts a PPMd block: `flags` is the block's first byte. With bit 0x20 a new model is set
    /// up (order from the low bits, memory from the next byte); with 0x40 the escape byte
    /// follows. Then the range decoder starts.
    pub(super) fn start(&mut self, inp: &mut Input, flags: u8, esc: &mut u8) -> Result<()> {
        let reset = flags & 0x20 != 0;
        let max_mb = if reset { Some(inp.byte()?) } else { None };
        if flags & 0x40 != 0 {
            *esc = inp.byte()?;
        }
        self.range_init(inp)?;
        if reset {
            let mut order = u32::from(flags & 0x1f) + 1;
            if order > 16 {
                order = 16 + (order - 16) * 3;
            }
            if order < 2 || order as usize > MAX_ORDER {
                return Err(Error::Corrupt("PPMd order"));
            }
            let size = (usize::from(max_mb.unwrap_or(0)) + 1) << 20;
            if size > MAX_MEMORY {
                return Err(Error::Corrupt("PPMd memory size"));
            }
            self.init(size as u32, order);
        } else if !self.ready {
            return Err(Error::Corrupt("PPMd block without a model"));
        }
        Ok(())
    }

    fn init(&mut self, size: u32, order: u32) {
        if self.size != size {
            self.mem = Vec::new();
            let align = 4 - (size & 3);
            // the spare unit past the pool (glue sentinel) and 8 bytes of slack for accessors
            self.mem = vec![0u8; (align + size + UNIT_SIZE) as usize + 8];
            self.max_off = self.mem.len() - 8;
            self.size = size;
            self.align = align;
        }
        self.max_order = order;
        self.restart_model();
        self.ready = true;
    }

    /// Decodes one symbol.
    #[inline]
    pub(super) fn decode(&mut self, inp: &mut Input) -> Result<u8> {
        let mc = self.min_context;
        if self.ns(mc) != 1 {
            let mut s = self.stats(mc);
            let summ = self.summ(mc);
            let count = self.threshold(summ)?;
            let mut hi = self.freq(s);
            if count < hi {
                self.rc_decode(0, hi);
                self.found_state = s;
                let sym = self.sym(s);
                self.update1_0();
                self.normalize(inp)?;
                return Ok(sym);
            }
            self.prev_success = 0;
            let n = self.ns(mc) as usize;
            if s as usize + n * 6 > self.max_off {
                return Err(Error::Corrupt("PPMd model"));
            }
            // the state array is inside the arena (checked above): walk it by pointer
            let base = unsafe { self.mem.as_ptr().add(s as usize + 1) };
            for k in 1..n {
                let f = u32::from(unsafe { *base.add(k * 6) });
                hi += f;
                if hi > count {
                    s += (k * 6) as u32;
                    self.rc_decode(hi - f, f);
                    self.found_state = s;
                    let sym = self.sym(s);
                    self.update1();
                    self.normalize(inp)?;
                    return Ok(sym);
                }
            }
            if count >= summ {
                return Err(Error::Corrupt("PPMd symbol"));
            }
            self.hi_bits_flag = u32::from(self.hb2flag[self.sym(self.found_state) as usize]);
            self.rc_decode(hi, summ - hi);
            let mut mask = [0xffu8; 256];
            let n = self.ns(mc);
            let first = self.stats(mc);
            for k in 0..n {
                mask[self.sym(first + k * 6) as usize] = 0;
            }
            return self.decode_escaped(inp, mask);
        } else {
            let one = mc + 2;
            self.hi_bits_flag = u32::from(self.hb2flag[self.sym(self.found_state) as usize]);
            let idx2 = self.prev_success as usize
                + self.ns2bsindx[self.ns(self.suffix(mc)) as usize - 1] as usize
                + self.hi_bits_flag as usize
                + 2 * self.hb2flag[self.sym(one) as usize] as usize
                + ((self.run_length >> 26) & 0x20) as usize;
            let idx1 = self.freq(one) as usize - 1;
            let prob = u32::from(self.bin_summ[idx1][idx2]);
            let size0 = (self.range >> 14).wrapping_mul(prob);
            let mean = (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS;
            if self.code.wrapping_sub(self.low) < size0 {
                self.range = size0;
                self.bin_summ[idx1][idx2] = (prob + (1 << INT_BITS) - mean) as u16;
                self.found_state = one;
                let sym = self.sym(one);
                self.update_bin();
                self.normalize(inp)?;
                return Ok(sym);
            }
            self.low = self.low.wrapping_add(size0);
            self.range = (self.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
            let np = prob - mean;
            self.bin_summ[idx1][idx2] = np as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(np >> 10) as usize]);
            let mut mask = [0xffu8; 256];
            mask[self.sym(one) as usize] = 0;
            self.prev_success = 0;
            return self.decode_escaped(inp, mask);
        }
    }

    /// Decoding after an escape: the symbols marked 0 in `mask` are excluded in the shorter
    /// contexts.
    fn decode_escaped(&mut self, inp: &mut Input, mut mask: [u8; 256]) -> Result<u8> {
        let mut ps = [0u32; 256];
        loop {
            self.normalize(inp)?;
            let num_masked = self.ns(self.min_context);
            loop {
                self.order_fall += 1;
                let suf = self.suffix(self.min_context);
                if suf == 0 {
                    return Err(Error::Corrupt("PPMd end of data"));
                }
                self.min_context = suf;
                if self.ns(suf) != num_masked {
                    break;
                }
            }
            let mc = self.min_context;
            let ns = self.ns(mc);
            let num = (ns - num_masked) as usize;
            let mut hi = 0u32;
            let mut s = self.stats(mc);
            let mut i = 0usize;
            while i != num {
                let m = mask[self.sym(s) as usize];
                if m != 0 {
                    hi += self.freq(s);
                    ps[i] = s;
                    i += 1;
                }
                s += 6;
            }
            let (see, esc) = self.make_esc_freq(num_masked);
            let freq_sum = esc + hi;
            let count = self.threshold(freq_sum)?;
            if count < hi {
                let mut acc = 0u32;
                let mut k = 0usize;
                loop {
                    acc += self.freq(ps[k]);
                    if acc > count {
                        break;
                    }
                    k += 1;
                }
                let s = ps[k];
                let f = self.freq(s);
                self.rc_decode(acc - f, f);
                if let Some((r, c)) = see {
                    let e = &mut self.see[r][c];
                    if u32::from(e.shift) < PERIOD_BITS {
                        e.count = e.count.wrapping_sub(1);
                        if e.count == 0 {
                            e.summ = e.summ.wrapping_shl(1);
                            e.count = (3u32 << e.shift) as u8;
                            e.shift += 1;
                        }
                    }
                }
                self.found_state = s;
                let sym = self.sym(s);
                self.update2();
                self.normalize(inp)?;
                return Ok(sym);
            }
            if count >= freq_sum {
                return Err(Error::Corrupt("PPMd escape"));
            }
            self.rc_decode(hi, freq_sum - hi);
            if let Some((r, c)) = see {
                let e = &mut self.see[r][c];
                e.summ = e.summ.wrapping_add(freq_sum as u16);
            }
            for &p in &ps[..num] {
                mask[self.sym(p) as usize] = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests;

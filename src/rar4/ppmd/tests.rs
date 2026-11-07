//! A test-only PPMd encoder mirroring `Ppmd::decode`, to run the model over data that
//! overflows small memory sizes (glue, restart) and compare with what is decoded. With
//! `RARCHIVE_EMIT_PPMD=<dir>` set, the streams are also written out (to be checked against the
//! official UnRAR by the scratch generator, and committed as test archives).
use super::*;

struct Enc {
    low: u32,
    range: u32,
    out: Vec<u8>,
}

impl Enc {
    fn new() -> Enc {
        Enc { low: 0, range: 0xffff_ffff, out: Vec::new() }
    }
    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return;
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.out.push((self.low >> 24) as u8);
            self.range <<= 8;
            self.low <<= 8;
        }
    }
    fn encode(&mut self, start: u32, size: u32, total: u32) {
        self.range /= total;
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }
    fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.out.push((self.low >> 24) as u8);
            self.low <<= 8;
        }
        self.out
    }
}

impl Ppmd {
    fn encode_symbol(&mut self, sym: u8, rc: &mut Enc) {
        let mc = self.min_context;
        let mut mask = [0xffu8; 256];
        if self.ns(mc) != 1 {
            let mut s = self.stats(mc);
            let summ = self.summ(mc);
            if self.sym(s) == sym {
                rc.encode(0, self.freq(s), summ);
                self.found_state = s;
                self.update1_0();
                return;
            }
            self.prev_success = 0;
            let mut hi = self.freq(s);
            let mut i = self.ns(mc) - 1;
            loop {
                s += 6;
                if self.sym(s) == sym {
                    rc.encode(hi, self.freq(s), summ);
                    self.found_state = s;
                    self.update1();
                    return;
                }
                hi += self.freq(s);
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            self.hi_bits_flag = u32::from(self.hb2flag[self.sym(self.found_state) as usize]);
            rc.encode(hi, summ - hi, summ);
            let first = self.stats(mc);
            for k in 0..self.ns(mc) {
                mask[self.sym(first + k * 6) as usize] = 0;
            }
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
            let size0 = (rc.range >> 14).wrapping_mul(prob);
            let mean = (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS;
            if self.sym(one) == sym {
                rc.range = size0;
                self.bin_summ[idx1][idx2] = (prob + (1 << INT_BITS) - mean) as u16;
                self.found_state = one;
                self.update_bin();
                rc.normalize();
                return;
            }
            rc.low = rc.low.wrapping_add(size0);
            rc.range = (rc.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
            rc.normalize();
            let np = prob - mean;
            self.bin_summ[idx1][idx2] = np as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(np >> 10) as usize]);
            mask[self.sym(one) as usize] = 0;
            self.prev_success = 0;
        }
        loop {
            let num_masked = self.ns(self.min_context);
            loop {
                self.order_fall += 1;
                let suf = self.suffix(self.min_context);
                assert!(suf != 0, "symbol not in the order -1 context");
                self.min_context = suf;
                if self.ns(suf) != num_masked {
                    break;
                }
            }
            let mc = self.min_context;
            let ns = self.ns(mc);
            let first = self.stats(mc);
            let mut hi = 0u32;
            let mut start = 0u32;
            let mut hit = None;
            let mut live = Vec::new();
            for k in 0..ns {
                let s = first + k * 6;
                if mask[self.sym(s) as usize] != 0 {
                    if self.sym(s) == sym {
                        hit = Some(s);
                        start = hi;
                    }
                    hi += self.freq(s);
                    live.push(s);
                }
            }
            let (see, esc) = self.make_esc_freq(num_masked);
            let freq_sum = esc + hi;
            if let Some(s) = hit {
                rc.encode(start, self.freq(s), freq_sum);
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
                self.update2();
                return;
            }
            rc.encode(hi, freq_sum - hi, freq_sum);
            if let Some((r, c)) = see {
                let e = &mut self.see[r][c];
                e.summ = e.summ.wrapping_add(freq_sum as u16);
            }
            for &s in &live {
                mask[self.sym(s) as usize] = 0;
            }
        }
    }
}

/// Encodes `data` as a PPMd block (with its header bytes), model memory `mb` MB.
fn encode_block(data: &[u8], order: u32, mb: usize) -> Vec<u8> {
    let mut m = Ppmd::new();
    m.init((mb << 20) as u32, order);
    let mut rc = Enc::new();
    for &b in data {
        m.encode_symbol(b, &mut rc);
        if b == 2 {
            m.encode_symbol(1, &mut rc); // the escape byte is followed by 1
        }
    }
    let k = if order <= 16 { order } else { 16 + (order - 16) / 3 };
    let mut out = vec![0x80 | 0x20 | (k - 1) as u8, (mb - 1) as u8];
    out.extend(rc.finish());
    out
}

fn pseudo(seed: u32, n: usize, symbols: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            ((x >> 16) % symbols) as u8
        })
        .collect()
}

fn decode_block(block: &[u8], n: usize) -> Vec<u8> {
    let mut m = Ppmd::new();
    let mut buf = Vec::new();
    let mut src = std::io::Cursor::new(block.to_vec());
    let mut inp = Input::new(&mut buf, &mut src);
    let flags = inp.byte().unwrap();
    let mut esc = 2u8;
    m.start(&mut inp, flags, &mut esc).unwrap();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let c = m.decode(&mut inp).unwrap();
        if c == esc {
            assert_eq!(m.decode(&mut inp).unwrap(), 1);
        }
        out.push(c);
    }
    out
}

#[test]
fn small_models_overflow_glue_and_restart_and_still_round_trip() {
    for (order, mb, symbols, n) in [(8u32, 1usize, 64u32, 120_000usize), (4, 1, 256, 60_000), (16, 1, 16, 150_000), (64, 2, 8, 100_000), (2, 1, 256, 80_000)] {
        let data = pseudo(order * 7 + mb as u32, n, symbols);
        let block = encode_block(&data, order, mb);
        let mid = crate::rar4::debug_counters();
        assert!(decode_block(&block, n) == data, "order {order}, {mb} MB, {symbols} symbols");
        let after = crate::rar4::debug_counters();
        if let Ok(dir) = std::env::var("RARCHIVE_EMIT_PPMD") {
            let name = format!("ppmd-o{order}-{mb}mb-s{symbols}");
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.data")), &data).unwrap();
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.ppmd")), &block).unwrap();
            println!("{name}: restarts {} glues {} packed {}", after[8] - mid[8], after[9] - mid[9], block.len());
        }
    }
}

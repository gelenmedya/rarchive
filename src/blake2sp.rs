//! BLAKE2sp: eight BLAKE2s leaves over 64-byte blocks taken in turn, and a root hashing the
//! eight leaf digests. RAR 5 uses it instead of CRC32 when asked to (WinRAR "BLAKE2
//! checksum"). Written from RFC 7693 (BLAKE2s) and the BLAKE2 specification's tree
//! parameters (fanout 8, depth 2, inner length 32).

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// One BLAKE2s instance with tree parameters.
#[derive(Clone)]
struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; 64],
    len: usize,
    last_node: bool,
}

impl Blake2s {
    /// digest 32, no key, fanout 8, depth 2, leaf length 0, inner length 32.
    fn new(node_offset: u32, node_depth: u8, last_node: bool) -> Blake2s {
        let mut p = [0u8; 32];
        p[0] = 32; // digest length
        p[2] = 8; // fanout
        p[3] = 2; // depth
        p[8..12].copy_from_slice(&node_offset.to_le_bytes());
        p[14] = node_depth;
        p[15] = 32; // inner length
        let mut h = IV;
        for (i, w) in h.iter_mut().enumerate() {
            *w ^= u32::from_le_bytes(p[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Blake2s { h, t: 0, buf: [0; 64], len: 0, last_node }
    }

    fn compress(&mut self, block: &[u8; 64], last: bool) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last {
            v[14] = !v[14];
            if self.last_node {
                v[15] = !v[15];
            }
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// A block is compressed only once more data follows (the last one gets the final flag).
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == 64 {
                self.t += 64;
                let b = self.buf;
                self.compress(&b, false);
                self.len = 0;
            }
            let k = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + k].copy_from_slice(&data[..k]);
            self.len += k;
            data = &data[k..];
        }
    }

    fn finish(mut self) -> [u8; 32] {
        self.t += self.len as u64;
        self.buf[self.len..].fill(0);
        let b = self.buf;
        self.compress(&b, true);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Streaming BLAKE2sp.
#[derive(Clone)]
pub(crate) struct Hasher {
    leaves: [Blake2s; 8],
    /// position in the current 512-byte stripe
    pos: usize,
}

impl Hasher {
    pub(crate) fn new() -> Hasher {
        Hasher { leaves: std::array::from_fn(|i| Blake2s::new(i as u32, 0, i == 7)), pos: 0 }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let leaf = self.pos / 64;
            let k = (64 - self.pos % 64).min(data.len());
            self.leaves[leaf].update(&data[..k]);
            self.pos = (self.pos + k) % 512;
            data = &data[k..];
        }
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        let mut root = Blake2s::new(0, 1, true);
        for leaf in self.leaves {
            root.update(&leaf.finish());
        }
        root.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2s_rfc7693_abc() {
        // RFC 7693 appendix B: BLAKE2s-256("abc"), plain parameters
        let mut s = Blake2s { h: IV, t: 0, buf: [0; 64], len: 0, last_node: false };
        s.h[0] ^= 0x0101_0020;
        s.update(b"abc");
        let want = [
            0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F, 0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A,
            0x29, 0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
        ];
        assert_eq!(s.finish(), want);
    }

    #[test]
    fn split_updates_match_one_update() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut a = Hasher::new();
        a.update(&data);
        let mut b = Hasher::new();
        for c in data.chunks(77) {
            b.update(c);
        }
        assert_eq!(a.finish(), b.finish());
    }
}

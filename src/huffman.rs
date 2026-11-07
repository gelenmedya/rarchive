//! Canonical Huffman decoding: one table lookup for codes up to [`QB`] bits, a short
//! canonical scan for the rare longer ones.

use crate::bits::Bits;
use crate::error::{Error, Result};

pub(crate) const QB: u32 = 10;
pub(crate) const MAX_LEN: usize = 15;
/// Returned for bit patterns that start no code (damaged data).
pub(crate) const INVALID: u32 = 0xFFFF;

pub(crate) struct Huffman {
    /// `symbol << 4 | length`, or 0 when the code is longer than QB bits / invalid.
    lut: Box<[u32; 1 << QB]>,
    /// First canonical code of each length, left-aligned to MAX_LEN bits.
    first: [u32; MAX_LEN + 2],
    /// Index into `symbols` of each length's first symbol.
    first_index: [u16; MAX_LEN + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    pub(crate) fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u32; MAX_LEN + 1];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // Kraft: an oversubscribed code is damaged; incomplete codes are allowed.
        let mut space: i64 = 1 << MAX_LEN;
        for (len, &c) in counts.iter().enumerate().skip(1) {
            space -= (c as i64) << (MAX_LEN - len);
        }
        if space < 0 {
            return Err(Error::Corrupt("oversubscribed Huffman table"));
        }
        let mut next = [0u32; MAX_LEN + 1];
        let mut first = [0u32; MAX_LEN + 2];
        let mut first_index = [0u16; MAX_LEN + 1];
        let mut code = 0u32;
        let mut index = 0u16;
        for len in 1..=MAX_LEN {
            next[len] = code;
            first[len] = code << (MAX_LEN - len);
            first_index[len] = index;
            index += counts[len] as u16;
            code = (code + counts[len]) << 1;
        }
        // sentinel: everything at or above this is past the last code
        first[MAX_LEN + 1] = 1 << MAX_LEN;
        let mut symbols = vec![0u16; index as usize];
        let mut lut = Box::new([0u32; 1 << QB]);
        let mut slot = first_index;
        for (sym, &l) in lengths.iter().enumerate() {
            let len = l as usize;
            if len == 0 {
                continue;
            }
            symbols[slot[len] as usize] = sym as u16;
            slot[len] += 1;
            let c = next[len];
            next[len] += 1;
            if len as u32 <= QB {
                let shift = QB - len as u32;
                let start = (c << shift) as usize;
                let entry = (sym as u32) << 4 | len as u32;
                lut[start..start + (1usize << shift)].fill(entry);
            }
        }
        Ok(Huffman { lut, first, first_index, symbols })
    }

    #[inline(always)]
    pub(crate) fn decode(&self, b: &mut Bits) -> u32 {
        let e = self.lut[(b.bitbuf >> (64 - QB)) as usize];
        if e != 0 {
            b.consume(e & 15);
            e >> 4
        } else {
            self.decode_long(b)
        }
    }

    #[cold]
    #[inline(never)]
    fn decode_long(&self, b: &mut Bits) -> u32 {
        let peek = (b.bitbuf >> (64 - MAX_LEN)) as u32;
        for len in QB as usize + 1..=MAX_LEN {
            // codes of this length occupy [first[len], first[len] + count << (MAX_LEN-len))
            let count = self.first_index.get(len + 1).map_or(self.symbols.len() as u16, |&i| i) - self.first_index[len];
            let base = self.first[len];
            let span = (count as u32) << (MAX_LEN - len);
            if peek >= base && peek - base < span {
                let i = self.first_index[len] as u32 + ((peek - base) >> (MAX_LEN - len));
                b.consume(len as u32);
                return self.symbols[i as usize] as u32;
            }
        }
        INVALID
    }
}

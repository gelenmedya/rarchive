//! MSB-first bit reader with a 64-bit buffer refilled without branches.
//!
//! The input slice must carry at least [`PAD`] readable bytes past the real data: refills
//! load 8 bytes at a time and may run a few bytes past the end before the caller's
//! end-of-block check stops decoding.

pub(crate) const PAD: usize = 64;

pub(crate) struct Bits<'a> {
    buf: &'a [u8],
    /// Next byte to load.
    p: usize,
    /// Valid bits, left-aligned (the next bit is bit 63).
    pub(crate) bitbuf: u64,
    /// Number of valid bits in `bitbuf`.
    left: u32,
}

impl<'a> Bits<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        assert!(buf.len() >= PAD);
        let mut b = Bits { buf, p: 0, bitbuf: 0, left: 0 };
        b.refill();
        b
    }

    /// Tops the buffer up to at least 56 valid bits.
    #[inline(always)]
    pub(crate) fn refill(&mut self) {
        // Past the padding (damaged input only) the clamp re-reads the last bytes: garbage
        // bits, but in bounds; the caller's end-of-block check stops decoding.
        let p = self.p.min(self.buf.len() - 8);
        // SAFETY: p + 8 <= buf.len() (Bits::new requires at least 8 bytes)
        let w = u64::from_be_bytes(unsafe { self.buf.as_ptr().add(p).cast::<[u8; 8]>().read_unaligned() });
        self.bitbuf |= w >> self.left;
        self.p += ((63 - self.left) >> 3) as usize;
        self.left |= 56;
    }

    /// Position of the next unread bit.
    #[inline(always)]
    pub(crate) fn pos(&self) -> usize {
        self.p * 8 - self.left as usize
    }

    /// Reads `n` bits (0..=32). The caller guarantees `n` valid bits are buffered.
    #[inline(always)]
    pub(crate) fn read(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 32 && n <= self.left);
        let v = ((self.bitbuf >> 1) >> (63 - n)) as u32;
        self.bitbuf <<= n;
        self.left -= n;
        v
    }

    #[inline(always)]
    pub(crate) fn consume(&mut self, n: u32) {
        debug_assert!(n <= self.left);
        self.bitbuf <<= n;
        self.left -= n;
    }

    /// Skips `n` bits.
    pub(crate) fn skip(&mut self, mut n: usize) {
        while n > 0 {
            self.refill();
            let k = n.min(48);
            self.consume(k as u32);
            n -= k;
        }
    }

    /// Reads `n` bits (0..=32), refilling first.
    pub(crate) fn read_slow(&mut self, n: u32) -> u32 {
        self.refill();
        self.read(n)
    }
}

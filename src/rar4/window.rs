//! The sliding window (a power-of-two ring) the RAR 1.5-4 decoders write into, and how its
//! contents are handed on.
//!
//! Provenance: written for rarchive; the structure (ring window, flushing in order, overlapped
//! match copy by doubling) is the usual LZ77 decoder shape, nothing taken from a particular
//! implementation.

use crate::error::Result;

/// The largest window any RAR 1.5-4 stream needs (offsets reach 4 MB).
pub(super) const MAX_WINDOW: usize = 4 << 20;
const MIN_WINDOW: usize = 64 << 10;

pub(super) struct Win {
    pub(super) buf: Vec<u8>,
    pub(super) mask: usize,
    /// Bytes produced since the last reset.
    pub(super) pos: u64,
    /// Bytes already handed to the output (`pos - written` is held back).
    pub(super) written: u64,
}

impl Win {
    pub(super) fn new() -> Win {
        Win { buf: Vec::new(), mask: 0, pos: 0, written: 0 }
    }

    /// Makes the window big enough for `total` bytes of output (at most [`MAX_WINDOW`]).
    /// Contents are kept when it already is.
    pub(super) fn reserve(&mut self, total: u64) {
        let want = (total.min(MAX_WINDOW as u64) as usize).next_power_of_two().clamp(MIN_WINDOW, MAX_WINDOW);
        if self.buf.len() < want {
            self.buf = vec![0u8; want];
            self.mask = want - 1;
            self.pos = 0;
            self.written = 0;
        }
    }

    pub(super) fn reset(&mut self) {
        self.pos = 0;
        self.written = 0;
    }

    pub(super) fn size(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub(super) fn put(&mut self, b: u8) {
        let i = self.pos as usize & self.mask;
        self.buf[i] = b;
        self.pos += 1;
    }

    /// Appends a match: `len` bytes from `dist` bytes back. `false` when `dist` reaches
    /// before the start of the data or beyond the window.
    #[inline(always)]
    pub(super) fn copy(&mut self, dist: usize, len: usize) -> bool {
        let size = self.buf.len();
        if dist == 0 || dist > size || dist as u64 > self.pos {
            return false;
        }
        let d = self.pos as usize & self.mask;
        let s = d.wrapping_sub(dist) & self.mask;
        if d + len <= size && s + len <= size {
            // the source ends before the destination, or lies ahead of it (a byte-wise copy
            // and a memmove agree on both)
            if s + len <= d {
                // SAFETY: d + len <= size and s + len <= d: both ranges are inside buf and
                // do not overlap
                unsafe {
                    let p = self.buf.as_mut_ptr();
                    copy_apart(p.add(s), p.add(d), len);
                }
            } else if s > d {
                self.buf.copy_within(s..s + len, d);
            } else if dist == 1 {
                let b = self.buf[s];
                self.buf[d..d + len].fill(b);
            } else {
                // overlapping: the run repeats with period `dist`; doubling what is in place
                let mut done = dist.min(len);
                self.buf.copy_within(s..s + done, d);
                while done < len {
                    let n = done.min(len - done);
                    self.buf.copy_within(d..d + n, d + done);
                    done += n;
                }
            }
        } else {
            for i in 0..len {
                let b = self.buf[(s + i) & self.mask];
                self.buf[(d + i) & self.mask] = b;
            }
        }
        self.pos += len as u64;
        true
    }

    /// Hands bytes `from..to` (absolute positions) to `out`.
    pub(super) fn emit(&self, from: u64, to: u64, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut p = from;
        while p < to {
            let i = p as usize & self.mask;
            let n = ((to - p) as usize).min(self.buf.len() - i);
            out(&self.buf[i..i + n])?;
            p += n as u64;
        }
        Ok(())
    }

    /// Appends bytes `from..to` to `dst`.
    pub(super) fn gather(&self, from: u64, to: u64, dst: &mut Vec<u8>) {
        let mut p = from;
        while p < to {
            let i = p as usize & self.mask;
            let n = ((to - p) as usize).min(self.buf.len() - i);
            dst.extend_from_slice(&self.buf[i..i + n]);
            p += n as u64;
        }
    }
}

/// Copies `len` bytes between ranges that don't overlap, short ones with a couple of
/// fixed-size moves (no call, no loop).
///
/// # Safety
/// `src..src + len` and `dst..dst + len` must be valid and disjoint.
#[inline(always)]
unsafe fn copy_apart(src: *const u8, dst: *mut u8, len: usize) {
    // SAFETY: the caller guarantees both ranges; every access below stays inside them
    unsafe {
        if len >= 16 {
            std::ptr::copy_nonoverlapping(src, dst, len);
        } else if len >= 8 {
            let a = src.cast::<u64>().read_unaligned();
            let b = src.add(len - 8).cast::<u64>().read_unaligned();
            dst.cast::<u64>().write_unaligned(a);
            dst.add(len - 8).cast::<u64>().write_unaligned(b);
        } else if len >= 4 {
            let a = src.cast::<u32>().read_unaligned();
            let b = src.add(len - 4).cast::<u32>().read_unaligned();
            dst.cast::<u32>().write_unaligned(a);
            dst.add(len - 4).cast::<u32>().write_unaligned(b);
        } else {
            for i in 0..len {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

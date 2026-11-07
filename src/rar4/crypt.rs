//! RAR 3.x / 4.x encryption: the SHA-1 based key derivation (2^18 rounds over the UTF-16
//! password and the salt), and AES-128-CBC.
//!
//! Provenance: the layout of the derivation (counter bytes, IV bytes taken every 2^14
//! rounds, the key's byte-swapped words) follows the `rars` crate's `crypto/rar30` module
//! (Apache-2.0) and the format description in libarchive's notes. SHA-1 itself comes from
//! the `sha1` crate (hardware accelerated where the processor has it). For key material of
//! 64 bytes or more (passwords of 28+ characters with the salt) the original tool feeds
//! SHA-1's blocks from a buffer it rewrites after each round, which `derive` reproduces as
//! `rars` does; that path is checked against the official UnRAR (tests/rar4.rs, the
//! `enc-long` archive).

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use sha1::{Digest, Sha1};

const ROUNDS: u32 = 1 << 18;
const MAX_PASSWORD_CHARS: usize = 127;

/// AES-128 key and CBC start value derived from a password and salt.
pub(crate) struct Key {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

/// The password as the key derivation takes it: UTF-16LE, at most 127 characters.
fn password_bytes(password: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(password);
    let mut out = Vec::with_capacity(password.len() * 2);
    for c in text.chars().take(MAX_PASSWORD_CHARS) {
        let mut u = [0u16; 2];
        for unit in c.encode_utf16(&mut u) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
    }
    out
}

pub(crate) fn derive(password: &[u8], salt: &[u8; 8]) -> Key {
    let mut raw = password_bytes(password);
    raw.extend_from_slice(salt);
    let n = raw.len();
    let mut sha = Sha1::new();
    let mut total = 0u64;
    let mut iv = [0u8; 16];
    let slow = n >= 64;
    for i in 0..ROUNDS {
        sha.update(&raw[..n]);
        if slow {
            // the original rewrites the complete blocks it hashed straight from this buffer
            let end = (total + n as u64) & !63;
            if end > total + 64 {
                let mut cur = (total & !63) + 64;
                while cur != end {
                    let off = (cur - total) as usize;
                    rewrite_block(&mut raw[off..off + 64]);
                    cur += 64;
                }
            }
        }
        total += n as u64;
        sha.update([i as u8, (i >> 8) as u8, (i >> 16) as u8]);
        total += 3;
        if i % (ROUNDS / 16) == 0 {
            iv[(i / (ROUNDS / 16)) as usize] = sha.clone().finalize()[19];
        }
    }
    let digest = sha.finalize();
    let mut key = [0u8; 16];
    for (k, d) in key.chunks_exact_mut(4).zip(digest.chunks_exact(4)) {
        k.copy_from_slice(&[d[3], d[2], d[1], d[0]]);
    }
    Key { key, iv }
}

/// Replaces a 64-byte block with the last 16 words of its SHA-1 message schedule.
fn rewrite_block(block: &mut [u8]) {
    let mut w = [0u32; 80];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    for (i, word) in w[64..80].iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// AES-128-CBC decryption of whole blocks, continuing the chain.
pub(crate) struct Decrypt {
    cipher: Aes128,
    iv: [u8; 16],
    blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>>,
}

impl Decrypt {
    pub(crate) fn new(key: &Key) -> Decrypt {
        Decrypt { cipher: Aes128::new((&key.key).into()), iv: key.iv, blocks: Vec::new() }
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        let n = data.len() / 16;
        self.blocks.clear();
        self.blocks.extend(data.chunks_exact(16).map(|c| *GenericArray::from_slice(c)));
        // the block decryptions are independent: one call lets AES-NI pipeline them
        self.cipher.decrypt_blocks(&mut self.blocks);
        let mut prev = self.iv;
        for i in 0..n {
            let c: [u8; 16] = data[i * 16..i * 16 + 16].try_into().unwrap();
            for (k, b) in data[i * 16..i * 16 + 16].iter_mut().enumerate() {
                *b = self.blocks[i][k] ^ prev[k];
            }
            prev = c;
        }
        self.iv = prev;
    }
}

/// A reader that decrypts what it reads (the inner stream holds whole blocks).
pub(crate) struct DecryptReader<R> {
    inner: R,
    dec: Decrypt,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
}

impl<R: std::io::Read> DecryptReader<R> {
    pub(crate) fn new(inner: R, key: &Key) -> Self {
        DecryptReader { inner, dec: Decrypt::new(key), buf: vec![0; 64 << 10], pos: 0, len: 0 }
    }
}

impl<R: std::io::Read> std::io::Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos == self.len {
            let mut n = 0;
            while n < self.buf.len() {
                let k = self.inner.read(&mut self.buf[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
                if n % 16 == 0 && n >= 4096 {
                    break;
                }
            }
            let whole = n - n % 16;
            if whole == 0 {
                return Ok(0);
            }
            self.dec.apply(&mut self.buf[..whole]);
            self.pos = 0;
            self.len = whole;
        }
        let k = out.len().min(self.len - self.pos);
        out[..k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

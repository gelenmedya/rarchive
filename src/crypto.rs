//! RAR 5 encryption: PBKDF2-HMAC-SHA256 keys, password check values, AES-256-CBC.
//!
//! The `aes` and `sha2` crates pick AES-NI / SHA extensions at run time when the processor
//! has them.

use std::io::{self, Read};

use aes::Aes256;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Iteration counts above 2^24 are refused (an archive can't make us spin for minutes).
const MAX_KDF_LOG: u8 = 24;
/// RAR uses at most this many bytes of a password.
const MAX_PASSWORD: usize = 127;

/// Everything derived from a password and salt.
#[derive(Clone)]
pub(crate) struct Keys {
    pub key: [u8; 32],
    /// Key for the checksums of files whose checksums are hidden (MAC'ed).
    pub hash_key: [u8; 32],
    check: [u8; 8],
}

/// Encryption parameters of one member (from its extra area) or of the headers.
#[derive(Clone, Debug)]
pub(crate) struct Params {
    pub kdf_log: u8,
    pub salt: [u8; 16],
    /// Data IV (members only; header blocks carry their own).
    pub iv: [u8; 16],
    /// Stored password check (8 bytes + 4 bytes of its SHA-256), when present.
    pub check: Option<[u8; 12]>,
    /// Checksums are MAC'ed with the hash key.
    pub mac_checksums: bool,
}

/// PBKDF2-HMAC-SHA256 with 2^log iterations for the key; the same chain run 16 and 32
/// iterations further gives the hash key and the password check value.
pub(crate) fn derive(password: &[u8], salt: &[u8; 16], log: u8) -> Result<Keys> {
    if log > MAX_KDF_LOG {
        return Err(Error::Corrupt("encryption iteration count"));
    }
    let password = &password[..password.len().min(MAX_PASSWORD)];
    // keyed once; each iteration clones the keyed state instead of re-keying
    let mac = <HmacSha256 as Mac>::new_from_slice(password).expect("any key length");
    let mut first = [0u8; 20];
    first[..16].copy_from_slice(salt);
    first[16..].copy_from_slice(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.clone().chain_update(first).finalize().into_bytes().into();
    let mut acc = u;
    let mut taps = [[0u8; 32]; 3];
    let mut rounds = (1u32 << log) - 1;
    for tap in &mut taps {
        for _ in 0..rounds {
            u = mac.clone().chain_update(u).finalize().into_bytes().into();
            for (a, b) in acc.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        *tap = acc;
        rounds = 16;
    }
    let mut check = [0u8; 8];
    for (i, c) in check.iter_mut().enumerate() {
        *c = taps[2][i] ^ taps[2][i + 8] ^ taps[2][i + 16] ^ taps[2][i + 24];
    }
    Ok(Keys { key: taps[0], hash_key: taps[1], check })
}

impl Keys {
    /// Whether these keys match a stored check value. An all-zero or self-inconsistent
    /// value can't tell: those count as a match (the data checksums decide then).
    pub(crate) fn matches(&self, stored: &[u8; 12]) -> bool {
        if stored[..8] == [0; 8] || Sha256::digest(&stored[..8])[..4] != stored[8..] {
            return true;
        }
        stored[..8] == self.check
    }

    /// A BLAKE2sp digest as stored for a file with MAC'ed checksums.
    pub(crate) fn mac_hash(&self, d: &[u8; 32]) -> [u8; 32] {
        <HmacSha256 as Mac>::new_from_slice(&self.hash_key).expect("any key length").chain_update(d).finalize().into_bytes().into()
    }

    /// A CRC32 as stored for a file with MAC'ed checksums.
    pub(crate) fn mac_crc(&self, crc: u32) -> u32 {
        let d = <HmacSha256 as Mac>::new_from_slice(&self.hash_key).expect("any key length").chain_update(crc.to_le_bytes()).finalize().into_bytes();
        d.chunks_exact(4).fold(0, |a, c| a ^ u32::from_le_bytes(c.try_into().unwrap()))
    }
}

/// AES-256-CBC decryption of a stream whose length is a multiple of 16.
pub(crate) struct Decrypt {
    cipher: Aes256,
    iv: [u8; 16],
    blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>>,
}

impl Decrypt {
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Decrypt {
        Decrypt { cipher: Aes256::new(key.into()), iv: *iv, blocks: Vec::new() }
    }

    /// Decrypts `data` (whole blocks) in place, continuing the chain.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        debug_assert!(data.len() % 16 == 0);
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

impl<R: Read> DecryptReader<R> {
    pub(crate) fn new(inner: R, key: &[u8; 32], iv: &[u8; 16]) -> Self {
        DecryptReader { inner, dec: Decrypt::new(key, iv), buf: vec![0; 64 << 10], pos: 0, len: 0 }
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.len {
            // fill whole blocks
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
                return Ok(0); // end (a partial trailing block is damaged data: ignored)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value_round_trip() {
        let k = derive(b"secret", &[7; 16], 4).unwrap();
        let mut stored = [0u8; 12];
        stored[..8].copy_from_slice(&k.check);
        stored[8..].copy_from_slice(&Sha256::digest(k.check)[..4]);
        assert!(k.matches(&stored));
        let other = derive(b"Secret", &[7; 16], 4).unwrap();
        assert!(!other.matches(&stored));
    }

    #[test]
    fn pbkdf2_chain_matches_direct_computation() {
        // the PBKDF2 chain against a direct two-iteration computation
        let k1 = derive(b"pw", &[1; 16], 1).unwrap(); // 2 iterations
        let mac = <HmacSha256 as Mac>::new_from_slice(b"pw").unwrap();
        let mut first = [1u8; 20];
        first[16..].copy_from_slice(&1u32.to_be_bytes());
        let u1: [u8; 32] = mac.clone().chain_update(first).finalize().into_bytes().into();
        let u2: [u8; 32] = mac.clone().chain_update(u1).finalize().into_bytes().into();
        let want: Vec<u8> = u1.iter().zip(u2).map(|(a, b)| a ^ b).collect();
        assert_eq!(k1.key.to_vec(), want);
    }
}

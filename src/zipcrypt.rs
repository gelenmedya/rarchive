//! ZIP encryption: traditional PKWARE ("ZipCrypto") and WinZip AES (AE-1 / AE-2).
//!
//! References: PKWARE APPNOTE 6.2 section on traditional encryption; WinZip's AES
//! specification (salt + 2-byte verifier, PBKDF2-HMAC-SHA1 with 1000 rounds, AES-CTR with a
//! little-endian counter starting at 1, HMAC-SHA1 over the ciphertext truncated to 10
//! bytes); the counter convention was cross-checked against the `zip` crate (MIT).

use std::io::{self, Read};

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

// ------------------------------------------------------------------ ZipCrypto

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC: [u32; 256] = crc_table();

#[derive(Clone)]
struct Keys([u32; 3]);

impl Keys {
    fn new(password: &[u8]) -> Keys {
        let mut k = Keys([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            k.update(b);
        }
        k
    }
    #[inline(always)]
    fn update(&mut self, b: u8) {
        let [k0, k1, k2] = &mut self.0;
        *k0 = CRC[((*k0 ^ b as u32) & 0xff) as usize] ^ (*k0 >> 8);
        *k1 = k1.wrapping_add(*k0 & 0xff).wrapping_mul(134_775_813).wrapping_add(1);
        *k2 = CRC[((*k2 ^ (*k1 >> 24)) & 0xff) as usize] ^ (*k2 >> 8);
    }
    #[inline(always)]
    fn decrypt(&mut self, c: u8) -> u8 {
        let t = (self.0[2] | 2) as u16;
        let p = c ^ (t.wrapping_mul(t ^ 1) >> 8) as u8;
        self.update(p);
        p
    }
}

/// Reads the 12-byte encryption header and checks the password against its last byte
/// (`check`: the CRC's top byte, or the DOS time's high byte with a data descriptor).
/// One wrong password in 256 passes this check: the CRC catches the rest.
pub(crate) struct ZipCryptoReader<R> {
    inner: R,
    keys: Keys,
}

impl<R: Read> ZipCryptoReader<R> {
    pub(crate) fn new(mut inner: R, password: &[u8], check: u8) -> Result<Self> {
        let mut keys = Keys::new(password);
        let mut head = [0u8; 12];
        inner.read_exact(&mut head)?;
        let mut last = 0;
        for &c in &head {
            last = keys.decrypt(c);
        }
        if last != check {
            return Err(Error::BadPassword);
        }
        Ok(ZipCryptoReader { inner, keys })
    }
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for b in &mut buf[..n] {
            *b = self.keys.decrypt(*b);
        }
        Ok(n)
    }
}

// ------------------------------------------------------------------ WinZip AES

enum Cipher {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Cipher {
    fn encrypt(&self, blocks: &mut [GenericArray<u8, aes::cipher::consts::U16>]) {
        match self {
            Cipher::A128(c) => c.encrypt_blocks(blocks),
            Cipher::A192(c) => c.encrypt_blocks(blocks),
            Cipher::A256(c) => c.encrypt_blocks(blocks),
        }
    }
}

/// Salt length for an AES strength (1 = 128, 2 = 192, 3 = 256 bits).
pub(crate) fn aes_salt_len(strength: u8) -> Result<usize> {
    match strength {
        1 => Ok(8),
        2 => Ok(12),
        3 => Ok(16),
        _ => Err(Error::Unsupported("ZIP AES strength")),
    }
}

/// Bytes an AES member adds around its data: salt, verifier, authentication code.
pub(crate) fn aes_overhead(strength: u8) -> Result<u64> {
    Ok(aes_salt_len(strength)? as u64 + 2 + 10)
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    let mac = <HmacSha1 as Mac>::new_from_slice(password).expect("any key length");
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let mut u: [u8; 20] = mac.clone().chain_update(salt).chain_update((i as u32 + 1).to_be_bytes()).finalize().into_bytes().into();
        let mut acc = u;
        for _ in 1..rounds {
            u = mac.clone().chain_update(u).finalize().into_bytes().into();
            for (a, b) in acc.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&acc[..chunk.len()]);
    }
}

/// Decrypts a WinZip AES member's data (between the verifier and the authentication code)
/// and authenticates it as it goes.
pub(crate) struct AesReader<R> {
    inner: R,
    cipher: Cipher,
    mac: HmacSha1,
    counter: u128,
    blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>>,
    /// unused keystream from the last batch
    stream: Vec<u8>,
    spos: usize,
}

impl<R: Read> AesReader<R> {
    /// Reads salt and verifier from `inner` and checks the password.
    pub(crate) fn new(mut inner: R, password: &[u8], strength: u8) -> Result<Self> {
        let salt_len = aes_salt_len(strength)?;
        let key_len = salt_len * 2;
        let mut salt = [0u8; 16];
        inner.read_exact(&mut salt[..salt_len])?;
        let mut verifier = [0u8; 2];
        inner.read_exact(&mut verifier)?;
        let mut dk = [0u8; 66];
        let dk = &mut dk[..2 * key_len + 2];
        pbkdf2_sha1(password, &salt[..salt_len], 1000, dk);
        if dk[2 * key_len..] != verifier {
            return Err(Error::BadPassword);
        }
        let key = &dk[..key_len];
        let cipher = match strength {
            1 => Cipher::A128(aes::Aes128::new_from_slice(key).unwrap()),
            2 => Cipher::A192(aes::Aes192::new_from_slice(key).unwrap()),
            _ => Cipher::A256(aes::Aes256::new_from_slice(key).unwrap()),
        };
        let mac = <HmacSha1 as Mac>::new_from_slice(&dk[key_len..2 * key_len]).expect("any key length");
        Ok(AesReader { inner, cipher, mac, counter: 1, blocks: Vec::new(), stream: Vec::new(), spos: 0 })
    }

    /// The authentication code of everything read so far (the stored one follows the data).
    pub(crate) fn code(self) -> [u8; 10] {
        self.mac.finalize().into_bytes()[..10].try_into().unwrap()
    }
}

impl<R: Read> Read for AesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.mac.update(&buf[..n]);
        let mut i = 0;
        while i < n {
            if self.spos == self.stream.len() {
                // a batch of counter blocks, encrypted in one call
                let blocks = ((n - i).div_ceil(16)).clamp(1, 4096);
                self.blocks.clear();
                for _ in 0..blocks {
                    self.blocks.push(GenericArray::clone_from_slice(&self.counter.to_le_bytes()));
                    self.counter += 1;
                }
                self.cipher.encrypt(&mut self.blocks);
                self.stream.clear();
                for b in &self.blocks {
                    self.stream.extend_from_slice(b);
                }
                self.spos = 0;
            }
            let k = (n - i).min(self.stream.len() - self.spos);
            for (d, s) in buf[i..i + k].iter_mut().zip(&self.stream[self.spos..self.spos + k]) {
                *d ^= s;
            }
            i += k;
            self.spos += k;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_sha1_rfc6070() {
        // RFC 6070 test vector 2: "password" / "salt", 2 iterations, 20 bytes
        let mut out = [0u8; 20];
        pbkdf2_sha1(b"password", b"salt", 2, &mut out);
        let want = [0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57];
        assert_eq!(out, want);
    }
}

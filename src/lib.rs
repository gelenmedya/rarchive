//! rarchive: a pure-Rust archive reader built for speed and for staying out of the way:
//! independent members (and the blocks of RAR 5 streams) decode in parallel, at low
//! priority, within a memory budget.
//!
//! Formats:
//! * RAR 5 (written from the public format description: stored and compressed members, solid
//!   streams, DELTA / E8 / E8E9 / ARM filters, AES-256 encryption with encrypted headers,
//!   volume sets, BLAKE2sp checksums).
//! * RAR 1.5-4.x (unpack versions 15, 20, 26, 29 and 36: LZ, PPMd, the standard RarVM filters,
//!   AES-128 encryption, volume sets).
//! * ZIP (stored, Deflate, Deflate64, bzip2, LZMA, zstd, xz, PPMd; ZipCrypto and WinZip AES;
//!   ZIP64; split and spanned sets).
//! * 7z (LZMA, LZMA2, PPMd, the BCJ family, BCJ2, Delta, Deflate, Deflate64, BZip2, Zstd,
//!   AES-256 including encrypted names).
//!
//! Not supported: RAR 1.3/1.4, the RAR 1.5/2.0 encryption, custom RarVM programs, RAR 7
//! dictionaries over 4 GB, PKWARE strong encryption. [`Archive::unsupported`] says which member
//! can't be extracted and why, before anything is decoded.

mod archive;
mod bits;
mod blake2sp;
mod cpu;
mod crypto;
mod error;
mod filter;
mod huffman;
mod lzma;
mod rar4;
mod unpack5;
#[doc(hidden)]
pub mod sevenz;
mod volume;
mod zip;
mod zipcrypt;

pub use archive::{Archive, Entry, Sink};
pub use cpu::{Priority, available_memory, memory_budget, threads};
#[doc(hidden)]
pub use rar4::debug_counters;
pub use error::{Error, Result};

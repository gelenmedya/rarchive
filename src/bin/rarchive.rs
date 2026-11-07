//! rarchive command line: list, test and extract RAR archives.
//!
//!   rarchive l <archive>            list members
//!   rarchive t <archive> [runs]     decode everything, verify checksums, report speed
//!   rarchive x <archive> <dir>      extract into <dir>
//!
//! The password of an encrypted archive comes from the RARCHIVE_PASSWORD environment variable.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use rarchive::{Archive, Entry, Sink};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["l", a] => list(a),
        ["t", a] => test(a, 1),
        ["t", a, n] => test(a, n.parse().unwrap_or(1)),
        ["x", a, d] => extract(a, d),
        ["blocks", a] => blocks(a),
        ["7zseg", a] => rarchive::sevenz::debug_segments(std::path::Path::new(a)).map(|l| l.iter().for_each(|x| println!("{x}"))),
        _ => {
            eprintln!("usage: rarchive l <archive> | rarchive t <archive> [runs] | rarchive x <archive> <dir>");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rarchive: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open(a: &str) -> rarchive::Result<Archive> {
    Archive::open_with_password(a, std::env::var("RARCHIVE_PASSWORD").ok().as_deref())
}

fn list(a: &str) -> rarchive::Result<()> {
    let ar = open(a)?;
    println!("{} members{}", ar.entries().len(), if ar.is_solid() { ", solid" } else { "" });
    for e in ar.entries() {
        println!(
            "{:>12} {:>12} m{} d{:>6}K {}{}{}",
            e.size,
            e.packed_size,
            e.method,
            e.dict_size >> 10,
            if e.blake2sp.is_some() { "[blake2] " } else { "" },
            e.name,
            if e.is_dir { "/" } else { "" }
        );
    }
    Ok(())
}

struct Count(u64);
impl Sink for Count {
    fn begin(&mut self, _: &Entry) -> std::io::Result<bool> {
        Ok(true)
    }
    fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.0 += b.len() as u64;
        Ok(())
    }
    fn end(&mut self, _: &Entry) -> std::io::Result<()> {
        Ok(())
    }
}

fn test(a: &str, runs: u32) -> rarchive::Result<()> {
    let mut best = f64::MAX;
    let mut bytes = 0;
    for _ in 0..runs.max(1) {
        let t = Instant::now();
        let ar = open(a)?;
        let mut c = Count(0);
        ar.extract(&mut c)?;
        best = best.min(t.elapsed().as_secs_f64());
        bytes = c.0;
    }
    println!("ok: {:.1} MB in {:.3} s ({:.0} MB/s)", bytes as f64 / 1e6, best, bytes as f64 / 1e6 / best);
    Ok(())
}

struct ToDisk {
    root: PathBuf,
    file: Option<BufWriter<File>>,
}

impl Sink for ToDisk {
    fn begin(&mut self, e: &Entry) -> std::io::Result<bool> {
        let Some(rel) = safe_path(&e.name) else {
            eprintln!("skipped unsafe path: {}", e.name);
            return Ok(false);
        };
        let path = self.root.join(rel);
        if e.is_dir {
            std::fs::create_dir_all(&path)?;
            return Ok(false);
        }
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        self.file = Some(BufWriter::with_capacity(1 << 20, File::create(&path)?));
        Ok(true)
    }
    fn data(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |f| f.write_all(b))
    }
    fn end(&mut self, _: &Entry) -> std::io::Result<()> {
        match self.file.take() {
            Some(mut f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// A member path that stays inside the destination: no roots, drives or `..`.
fn safe_path(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        let c = Path::new(part).components().next()?;
        match c {
            Component::Normal(_) if !part.contains(':') => out.push(part),
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

fn extract(a: &str, d: &str) -> rarchive::Result<()> {
    let t = Instant::now();
    let ar = open(a)?;
    let mut s = ToDisk { root: PathBuf::from(d), file: None };
    ar.extract(&mut s)?;
    println!("ok: {} members in {:.2} s", ar.entries().len(), t.elapsed().as_secs_f64());
    Ok(())
}

fn blocks(a: &str) -> rarchive::Result<()> {
    let ar = open(a)?;
    let stats = ar.block_stats()?;
    let (mut n, mut t, mut b) = (0usize, 0usize, 0u64);
    let mut biggest = (0usize, String::new());
    for (name, bn, bt, bb) in &stats {
        n += bn;
        t += bt;
        b += bb;
        if *bn > biggest.0 {
            biggest = (*bn, format!("{name}: {bn} blocks, {bt} with tables, {:.1} MB packed", *bb as f64 / 1e6));
        }
    }
    println!("{} members, {n} blocks ({t} with tables), avg {:.0} KB packed per block", stats.len(), b as f64 / n.max(1) as f64 / 1e3);
    println!("most blocks: {}", biggest.1);
    Ok(())
}

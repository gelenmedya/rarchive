//! Block-parallel decoding.
//!
//! A RAR 5 block's symbols can be read without its output: Huffman codes, lengths and
//! distances come from the bit stream alone (repeat distances stay symbolic until the
//! window state is known). And every block states its packed size, so the blocks of a
//! member can be found by reading headers only.
//!
//! So decoding splits in three:
//! * a reader thread walks the packed data, reads each block (and its Huffman tables,
//!   a small serial step), and hands it out;
//! * parser threads turn blocks into command lists ([`Parsed`]) in parallel;
//! * the calling thread applies the commands in order to the window (literal runs are
//!   plain copies, matches the usual window copy), runs filters, and feeds the sink.
//!
//! Solid archives and single large members gain the most: before this, a solid stream
//! had to run on one thread.

use std::collections::BTreeMap;

use std::io::Read;

use std::sync::mpsc::{Receiver, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex};

use super::{
    Block, CHUNK, LEN_BASE, LEN_BITS, LEN_SIZE, MAIN_SIZE, MAX_FILTERS, Tables, Unpack5, copy_match, read_block,
    read_tables,
};
use crate::bits::Bits;
use crate::error::{Error, Result};
use crate::filter::{self, Filter, Kind};

/// One step, packed into 8 bytes (the applier streams millions of them): `lits` literal
/// bytes (16 bits), then the action named by `dist` (35 bits) with `len` (13 bits: a match
/// length, or for [`FILTER`] the index into [`Parsed::filters`]).
#[derive(Clone, Copy)]
pub(crate) struct Cmd(u64);

impl Cmd {
    #[inline(always)]
    fn new(lits: usize, len: usize, dist: u64) -> Cmd {
        debug_assert!(lits <= MAX_LITS && len < 1 << 13 && dist < 1 << 35);
        Cmd(lits as u64 | (len as u64) << 16 | dist << 29)
    }
    #[inline(always)]
    fn lits(self) -> usize {
        (self.0 & 0xFFFF) as usize
    }
    #[inline(always)]
    fn len(self) -> usize {
        ((self.0 >> 16) & 0x1FFF) as usize
    }
    #[inline(always)]
    fn dist(self) -> u64 {
        self.0 >> 29
    }
}

const MAX_LITS: usize = 0xFFFF;

/// No action (trailing literals).
const NONE: u64 = 0;
/// Repeat distance `REP + i`, i in 0..4.
const REP: u64 = (1 << 35) - 8;
/// Symbol 257: repeat the last length at the last distance.
const LAST: u64 = (1 << 35) - 2;
const FILTER: u64 = (1 << 35) - 1;

/// Pushes a command, splitting literal runs longer than a command holds.
#[inline(always)]
fn push(cmds: &mut Vec<Cmd>, mut lits: usize, len: usize, dist: u64) {
    while lits > MAX_LITS {
        cmds.push(Cmd::new(MAX_LITS, 0, NONE));
        lits -= MAX_LITS;
    }
    cmds.push(Cmd::new(lits, len, dist));
}

#[derive(Default)]
pub(crate) struct Parsed {
    cmds: Vec<Cmd>,
    lits: Vec<u8>,
    /// (offset from the output position, length, kind)
    filters: Vec<(u32, u32, Kind)>,
}

/// Turns a block's symbols into commands. `payload` carries the block (plus padding),
/// symbols run from `start` to `end` (bits).
fn parse(payload: &[u8], start: usize, end: usize, t: &Tables, p: &mut Parsed) -> Result<()> {
    p.cmds.clear();
    p.lits.clear();
    p.filters.clear();
    // every symbol takes at least one bit: at most `end - start` literals
    p.lits.reserve(end - start + 16);
    let lp = p.lits.as_mut_ptr();
    let mut nl = 0usize;
    let mut run = 0usize;
    let mut b = Bits::new(payload);
    b.skip(start);
    let res = loop {
        if b.pos() >= end {
            break Ok(());
        }
        b.refill();
        let sym = t.main.decode(&mut b);
        if sym < 256 {
            // SAFETY: nl < reserved capacity (one literal per consumed bit at most)
            unsafe { *lp.add(nl) = sym as u8 };
            nl += 1;
            continue;
        }
        let lits = nl - run;
        run = nl;
        if sym >= 262 {
            if sym as usize >= MAIN_SIZE {
                break Err(Error::Corrupt("invalid code"));
            }
            let slot = (sym - 262) as usize;
            let mut len = LEN_BASE[slot] as usize + b.read(LEN_BITS[slot] as u32) as usize;
            let ds = t.dist.decode(&mut b);
            if ds >= t.dist_count {
                break Err(Error::Corrupt("invalid distance code"));
            }
            b.refill();
            let dist = if ds < 4 {
                ds as usize + 1
            } else {
                let nb = (ds - 2) >> 1;
                let base = ((2 | (ds as usize & 1)) << nb) + 1;
                if nb >= 4 && t.align_mode {
                    let hi = if nb > 4 { b.read(nb - 4) as usize } else { 0 };
                    let lo = t.align.decode(&mut b);
                    if lo >= 16 {
                        break Err(Error::Corrupt("invalid align code"));
                    }
                    base + (hi << 4 | lo as usize)
                } else if nb > 32 {
                    let hi = b.read(nb - 32) as usize;
                    b.refill();
                    base + (hi << 32 | b.read(32) as usize)
                } else {
                    base + b.read(nb) as usize
                }
            };
            len += (dist > 0x100) as usize + (dist > 0x2000) as usize + (dist > 0x40000) as usize;
            if dist as u64 >= REP {
                break Err(Error::Unsupported("distance beyond 32 GB"));
            }
            push(&mut p.cmds, lits, len, dist as u64);
            continue;
        }
        match sym {
            256 => {
                let offset = number(&mut b);
                let len = number(&mut b);
                let kind = match b.read_slow(3) {
                    0 => Kind::Delta { channels: b.read_slow(5) + 1 },
                    1 => Kind::E8,
                    2 => Kind::E8E9,
                    3 => Kind::Arm,
                    _ => break Err(Error::Corrupt("unknown filter")),
                };
                if p.filters.len() >= MAX_FILTERS {
                    break Err(Error::Corrupt("too many filters"));
                }
                push(&mut p.cmds, lits, p.filters.len(), FILTER);
                p.filters.push((offset, len, kind));
            }
            257 => push(&mut p.cmds, lits, 0, LAST),
            _ => {
                let ls = t.len.decode(&mut b);
                if ls as usize >= LEN_SIZE {
                    break Err(Error::Corrupt("invalid length code"));
                }
                let len = LEN_BASE[ls as usize] + b.read(LEN_BITS[ls as usize] as u32);
                push(&mut p.cmds, lits, len as usize, REP + (sym - 258) as u64);
            }
        }
    };
    // SAFETY: the first nl bytes were written above
    unsafe { p.lits.set_len(nl) };
    if nl > run {
        push(&mut p.cmds, nl - run, 0, NONE);
    }
    // padding, so the applier may copy short literal runs 16 bytes at a time
    p.lits.extend_from_slice(&[0; LIT_PAD]);
    res
}

const LIT_PAD: usize = 16;

fn number(b: &mut Bits) -> u32 {
    let n = b.read_slow(2) + 1;
    let mut v = 0u32;
    for i in 0..n {
        v |= b.read_slow(8) << (i * 8);
    }
    v
}

impl Unpack5 {
    /// Index just past which output must be handed on (and the ring folded).
    #[inline(always)]
    fn stop_wp(&self) -> usize {
        ((self.next_stop.max(self.lap) - self.lap) as usize).min(self.w)
    }

    /// Folds the ring, flushes, and sets the next stop.
    fn housekeep(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let _t = prof::Timer::new(&prof::FLUSH);
        if self.wp >= self.w {
            self.wrap();
        }
        let upto = self.pos().min(self.file_end);
        self.flush(upto, self.file_start, out)?;
        self.next_stop = self.file_end.min(self.pos() + CHUNK);
        Ok(())
    }

    /// Applies one parsed block to the current file. Output past the file end is ignored.
    ///
    /// Between housekeeping stops the loop works on locals: `wp < stop` means the write
    /// position is inside the ring and before the file end, so literal runs and matches
    /// can be written (with up to 16 bytes of overcopy into the slack area) unchecked.
    fn apply(&mut self, p: &Parsed, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let lits = p.lits.as_ptr();
        let lits_end = p.lits.len() - LIT_PAD;
        let mut li = 0usize;
        let mut wp = self.wp;
        let mut stop = self.stop_wp();
        let mut reps = self.reps;
        let mut last_len = self.last_len;
        // Re-establishes `wp < stop` after housekeeping; false when the file is complete.
        macro_rules! housekeep {
            () => {{
                self.wp = wp;
                self.housekeep(out)?;
                wp = self.wp;
                stop = self.stop_wp();
                self.pos() < self.file_end
            }};
        }
        let r = (|| -> Result<()> {
            for &c in &p.cmds {
                let mut n = c.lits();
                if li + n > lits_end {
                    return Err(Error::Corrupt("literal count"));
                }
                if n <= 16 && wp + n < stop {
                    // SAFETY: li + 16 <= lits.len() (padding); wp + 16 < w + SLACK
                    unsafe {
                        let v = std::ptr::read_unaligned(lits.add(li) as *const [u8; 16]);
                        std::ptr::write_unaligned(self.win.as_mut_ptr().add(wp) as *mut [u8; 16], v);
                    }
                    wp += n;
                    li += n;
                } else {
                    while n > 0 {
                        if wp >= stop && !housekeep!() {
                            return Ok(());
                        }
                        let k = n.min(stop - wp);
                        self.win[wp..wp + k].copy_from_slice(&p.lits[li..li + k]);
                        wp += k;
                        li += k;
                        n -= k;
                    }
                }
                let (dist, len) = match c.dist() {
                    NONE => continue,
                    FILTER => {
                        let (offset, len, kind) = p.filters[c.len()];
                        if len > filter::MAX_LEN {
                            return Err(Error::Corrupt("filter block too large"));
                        }
                        if self.filters.len() >= MAX_FILTERS {
                            return Err(Error::Corrupt("too many filters"));
                        }
                        let pos = self.lap + wp as u64;
                        self.filters.push_back(Filter { start: pos + offset as u64, len, kind });
                        continue;
                    }
                    LAST => {
                        if last_len == 0 {
                            continue;
                        }
                        (reps[0], last_len)
                    }
                    d if d >= REP => {
                        let i = (d - REP) as usize;
                        let dist = reps[i];
                        if dist == 0 {
                            return Err(Error::Corrupt("repeat distance before any match"));
                        }
                        let mut k = i;
                        while k > 0 {
                            reps[k] = reps[k - 1];
                            k -= 1;
                        }
                        reps[0] = dist;
                        last_len = c.len();
                        (dist, last_len)
                    }
                    d => {
                        reps = [d as usize, reps[0], reps[1], reps[2]];
                        last_len = c.len();
                        (d as usize, last_len)
                    }
                };
                if wp >= stop && !housekeep!() {
                    return Ok(());
                }
                // SAFETY: wp < stop <= w and len <= MAX_MATCH
                unsafe { copy_match(self.win.as_mut_ptr(), wp, dist, len, self.w) };
                wp += len;
            }
            Ok(())
        })();
        self.wp = wp;
        self.reps = reps;
        self.last_len = last_len;
        r?;
        if self.wp >= self.stop_wp() {
            self.housekeep(out)?;
        }
        Ok(())
    }
}

/// A member of a solid group, as the pipeline needs it.
pub(crate) struct Member {
    /// Where the packed data is (several volumes for a split member).
    pub parts: Vec<crate::volume::Part>,
    pub size: u64,
    pub stored: bool,
    pub solid: bool,
    pub algo: u8,
    pub is_dir: bool,
    /// AES key and IV of an encrypted member.
    pub crypt: Option<([u8; 32], [u8; 16])>,
}

/// Receives the group's members in order.
pub(crate) trait MemberSink {
    fn begin(&mut self, i: usize) -> Result<()>;
    fn data(&mut self, d: &[u8]) -> Result<()>;
    fn end(&mut self, i: usize) -> Result<()>;
}

enum Item {
    Begin(usize),
    Block(Box<Parsed>),
    Stored(Vec<u8>),
    End(usize),
}

/// Buffers handed back for reuse: fresh allocations per block cost page faults.
#[derive(Default)]
struct Pool {
    parsed: Mutex<Vec<Box<Parsed>>>,
    payloads: Mutex<Vec<Vec<u8>>>,
}

struct Job {
    seq: u64,
    payload: Vec<u8>,
    tables: Arc<Tables>,
    start: usize,
    end: usize,
}

/// Decodes a run of dependent members with `threads` parser threads.
pub(crate) fn decode_chain(
    volumes: &[std::path::PathBuf],
    members: &[Member],
    reach: u64,
    threads: usize,
    priority: crate::cpu::Priority,
    dec: &mut Unpack5,
    sink: &mut dyn MemberSink,
) -> Result<()> {
    // items in flight between the reader and the applier (bounds memory)
    let window = (threads * 8).max(32);
    let (tok_tx, tok_rx) = sync_channel::<()>(window);
    for _ in 0..window {
        tok_tx.send(()).unwrap();
    }
    let (job_tx, job_rx) = sync_channel::<Job>(threads * 2);
    let job_rx = Mutex::new(job_rx);
    let (res_tx, res_rx) = channel::<(u64, Result<Item>)>();
    let pool = Pool::default();
    std::thread::scope(|s| {
        // reader
        {
            let res_tx = res_tx.clone();
            let pool = &pool;
            s.spawn(move || {
                crate::cpu::apply_priority(priority);
                if let Err(e) = read_all(volumes, members, &tok_rx, &job_tx, &res_tx, pool) {
                    let _ = res_tx.send((u64::MAX, Err(e)));
                }
            });
        }
        // parsers
        for _ in 0..threads.max(1) {
            let res_tx = res_tx.clone();
            let job_rx = &job_rx;
            let pool = &pool;
            s.spawn(move || {
                crate::cpu::apply_priority(priority);
                loop {
                    let job = match job_rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => return,
                    };
                    let mut p = pool.parsed.lock().unwrap().pop().unwrap_or_default();
                    let r = parse(&job.payload, job.start, job.end, &job.tables, &mut p).map(|_| Item::Block(p));
                    pool.payloads.lock().unwrap().push(job.payload);
                    if res_tx.send((job.seq, r)).is_err() {
                        return;
                    }
                }
            });
        }
        drop(res_tx);
        let r = apply_all(members, reach, dec, sink, &res_rx, &tok_tx, &pool);
        // stop the others: they fail on their next send / receive
        drop(res_rx);
        drop(tok_tx);
        r
    })
}

/// The reader: walks the members' packed data in order.
fn read_all(
    volumes: &[std::path::PathBuf],
    members: &[Member],
    tok: &Receiver<()>,
    jobs: &SyncSender<Job>,
    res: &std::sync::mpsc::Sender<(u64, Result<Item>)>,
    pool: &Pool,
) -> Result<()> {
    let mut files = crate::volume::Files::new(volumes);
    let mut seq = 0u64;
    let stop = || Error::Corrupt("stopped");
    let direct = |seq: &mut u64, item: Item| -> Result<()> {
        tok.recv().map_err(|_| stop())?;
        res.send((*seq, Ok(item))).map_err(|_| stop())?;
        *seq += 1;
        Ok(())
    };
    let mut tables: Option<Arc<Tables>> = None;
    for (i, m) in members.iter().enumerate() {
        direct(&mut seq, Item::Begin(i))?;
        if !m.is_dir {
            let raw = files.reader(&m.parts);
            let mut src: Box<dyn Read + '_> = match &m.crypt {
                Some((key, iv)) => Box::new(crate::crypto::DecryptReader::new(raw, key, iv)),
                None => Box::new(raw),
            };
            if m.stored {
                let mut left = m.size;
                while left > 0 {
                    let n = left.min(1 << 20) as usize;
                    let mut buf = vec![0u8; n];
                    src.read_exact(&mut buf)?;
                    direct(&mut seq, Item::Stored(buf))?;
                    left -= n as u64;
                }
            } else {
                if !m.solid {
                    tables = None;
                }
                loop {
                    let mut payload = pool.payloads.lock().unwrap().pop().unwrap_or_default();
                    let Some(Block { last, tables: has, bits }) = read_block(&mut src, &mut payload)? else { break };
                    let mut start = 0;
                    if has {
                        let mut b = Bits::new(&payload);
                        tables = Some(Arc::new(read_tables(&mut b, bits, m.algo)?));
                        start = b.pos();
                    }
                    let t = tables.clone().ok_or(Error::Corrupt("block without Huffman tables"))?;
                    tok.recv().map_err(|_| stop())?;
                    jobs.send(Job { seq, payload, tables: t, start, end: bits }).map_err(|_| stop())?;
                    seq += 1;
                    if last {
                        break;
                    }
                }
            }
        }
        direct(&mut seq, Item::End(i))?;
    }
    Ok(())
}

/// The applier: takes parsed blocks back in order and runs them through the window.
fn apply_all(
    members: &[Member],
    reach: u64,
    dec: &mut Unpack5,
    sink: &mut dyn MemberSink,
    res: &Receiver<(u64, Result<Item>)>,
    tok: &SyncSender<()>,
    pool: &Pool,
) -> Result<()> {
    let mut next = 0u64;
    let mut pending: BTreeMap<u64, Item> = BTreeMap::new();
    let mut done = 0usize;
    let prof = std::env::var_os("RARCHIVE_PROF").is_some();
    let (mut waited, mut worked) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    let t0 = std::time::Instant::now();
    while done < members.len() {
        let tw = std::time::Instant::now();
        let (seq, item) = res.recv().map_err(|_| Error::Corrupt("decoder stopped"))?;
        waited += tw.elapsed();
        let tk = std::time::Instant::now();
        pending.insert(seq, item?);
        while let Some(item) = pending.remove(&next) {
            next += 1;
            let mut out = |d: &[u8]| sink.data(d);
            match item {
                Item::Begin(i) => {
                    sink.begin(i)?;
                    let m = &members[i];
                    if !m.is_dir && !m.stored {
                        dec.begin_file(m.size, reach, m.algo, m.solid)?;
                    }
                }
                Item::Block(p) => {
                    dec.apply(&p, &mut out)?;
                    pool.parsed.lock().unwrap().push(p);
                }
                Item::Stored(d) => out(&d)?,
                Item::End(i) => {
                    let m = &members[i];
                    if !m.is_dir && !m.stored {
                        dec.finish_file(&mut out)?;
                    }
                    sink.end(i)?;
                    done += 1;
                }
            }
            let _ = tok.send(());
        }
        worked += tk.elapsed();
    }
    if prof && t0.elapsed().as_millis() > 50 {
        eprintln!(
            "applier: {:.0} ms busy ({:.0} ms flushing: filters {:.0}, sink {:.0}), {:.0} ms waiting",
            worked.as_secs_f64() * 1e3,
            prof::take(&prof::FLUSH),
            prof::take(&prof::FILTER),
            prof::take(&prof::SINK),
            waited.as_secs_f64() * 1e3
        );
    }
    Ok(())
}

/// Coarse timers for `RARCHIVE_PROF=1` runs.
pub(crate) mod prof {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub(crate) static FLUSH: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FILTER: AtomicU64 = AtomicU64::new(0);
    pub(crate) static SINK: AtomicU64 = AtomicU64::new(0);
    pub(crate) struct Timer<'a>(&'a AtomicU64, std::time::Instant);
    impl<'a> Timer<'a> {
        pub(crate) fn new(c: &'a AtomicU64) -> Self {
            Timer(c, std::time::Instant::now())
        }
    }
    impl Drop for Timer<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(self.1.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn take(c: &AtomicU64) -> f64 {
        c.swap(0, Ordering::Relaxed) as f64 / 1e6
    }
}

//! `litework-pack` — LiteWork's format-aware, lossless packet archive (`.lwz`).
//!
//! Instead of feeding a capture to a general-purpose compressor as one byte
//! stream, the input is *shredded* into many homogeneous columns (one per
//! header field), header fields are predicted from per-flow state (so most of
//! them encode as zero), derivable fields (checksums, lengths) are replaced by
//! residuals, and payloads are grouped by protocol class and then by flow so
//! that similar bytes sit next to each other. Each column is then compressed
//! independently with LZMA.
//!
//! Everything is lossless to the byte: anything the modeller cannot parse is
//! stored verbatim in a raw column, and decoding is the exact inverse.
//!
//! Container layout (all integers little-endian):
//!
//! ```text
//! "LWZ1"  u8 version  u8 source_kind
//! repeated blocks:
//!   u64 items              (0 = end of archive)
//!   u32 ncols
//!   ncols × { u32 key, u8 codec, u64 raw_len, u64 comp_len, comp_len bytes }
//! ```
//!
//! Blocks are self-contained (flow tables reset per block), so a damaged
//! archive loses at most one block and future random access is possible.

pub mod jsonl;
pub mod packet;
pub mod pcap;

use std::collections::HashMap;
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"LWZ1";
pub const VERSION: u8 = 1;

pub const KIND_PCAP: u8 = 0;
pub const KIND_JSONL: u8 = 1;

const CODEC_RAW: u8 = 0;
const CODEC_LZMA: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("lzma error: {0}")]
    Lzma(String),
    #[error("archive format error: {0}")]
    Format(String),
    #[error("unsupported input: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, PackError>;

pub(crate) fn fmt_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(PackError::Format(msg.into()))
}

/// Tuning knobs for the encoder.
#[derive(Debug, Clone)]
pub struct PackOptions {
    /// LZMA effort 1..=9 (9 = slowest, smallest).
    pub level: u32,
    /// Approximate raw bytes per block; bounds encoder/decoder memory.
    pub block_bytes: usize,
    /// Worker threads used to compress a block's columns in parallel.
    pub threads: usize,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            level: 9,
            block_bytes: 128 << 20,
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
        }
    }
}

// ---------------------------------------------------------------------------
// Varint helpers
// ---------------------------------------------------------------------------

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

pub fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

// ---------------------------------------------------------------------------
// Column set (encoder side)
// ---------------------------------------------------------------------------

/// Write-side column set: a map from column key to a growing byte buffer.
#[derive(Default)]
pub struct Cols {
    map: HashMap<u32, usize>,
    keys: Vec<u32>,
    data: Vec<Vec<u8>>,
}

impl Cols {
    pub fn col(&mut self, key: u32) -> &mut Vec<u8> {
        let idx = match self.map.get(&key) {
            Some(&i) => i,
            None => {
                let i = self.data.len();
                self.map.insert(key, i);
                self.keys.push(key);
                self.data.push(Vec::new());
                i
            }
        };
        &mut self.data[idx]
    }
    pub fn u8(&mut self, key: u32, v: u8) {
        self.col(key).push(v);
    }
    pub fn u16(&mut self, key: u32, v: u16) {
        self.col(key).extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, key: u32, v: u32) {
        self.col(key).extend_from_slice(&v.to_le_bytes());
    }
    pub fn varint(&mut self, key: u32, v: u64) {
        put_varint(self.col(key), v);
    }
    pub fn zig(&mut self, key: u32, v: i64) {
        put_varint(self.col(key), zigzag(v));
    }
    pub fn bytes(&mut self, key: u32, b: &[u8]) {
        self.col(key).extend_from_slice(b);
    }
    /// Total raw bytes buffered across all columns.
    pub fn raw_len(&self) -> usize {
        self.data.iter().map(|d| d.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|d| d.is_empty())
    }
    fn take(&mut self) -> Vec<(u32, Vec<u8>)> {
        let keys = std::mem::take(&mut self.keys);
        let data = std::mem::take(&mut self.data);
        self.map.clear();
        keys.into_iter()
            .zip(data)
            .filter(|(_, d)| !d.is_empty())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Column set (decoder side)
// ---------------------------------------------------------------------------

pub(crate) struct Cursor {
    pub(crate) data: Vec<u8>,
    pub(crate) pos: usize,
}

/// Read-side column set: each column is a cursor over its decoded bytes.
#[derive(Default)]
pub struct ColReaders {
    map: HashMap<u32, Cursor>,
}

impl ColReaders {
    pub(crate) fn cur(&mut self, key: u32) -> Result<&mut Cursor> {
        match self.map.get_mut(&key) {
            Some(c) => Ok(c),
            None => fmt_err(format!("missing column {key:#x}")),
        }
    }
    pub fn u8(&mut self, key: u32) -> Result<u8> {
        let c = self.cur(key)?;
        if c.pos >= c.data.len() {
            return fmt_err(format!("column {key:#x} exhausted"));
        }
        let v = c.data[c.pos];
        c.pos += 1;
        Ok(v)
    }
    pub fn u16(&mut self, key: u32) -> Result<u16> {
        let b = self.take(key, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self, key: u32) -> Result<u32> {
        let b = self.take(key, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn varint(&mut self, key: u32) -> Result<u64> {
        let c = self.cur(key)?;
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            if c.pos >= c.data.len() {
                return fmt_err(format!("column {key:#x} exhausted in varint"));
            }
            let b = c.data[c.pos];
            c.pos += 1;
            if shift >= 64 {
                return fmt_err("varint overflow");
            }
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }
    pub fn zig(&mut self, key: u32) -> Result<i64> {
        Ok(unzigzag(self.varint(key)?))
    }
    /// Borrow the next `n` bytes of a column.
    pub fn take(&mut self, key: u32, n: usize) -> Result<&[u8]> {
        if n == 0 {
            // Columns that were empty for the whole block are never written.
            return Ok(&[]);
        }
        let c = self.cur(key)?;
        if c.pos + n > c.data.len() {
            return fmt_err(format!("column {key:#x} exhausted ({n} bytes)"));
        }
        let s = &c.data[c.pos..c.pos + n];
        c.pos += n;
        Ok(s)
    }
    /// Entire remaining bytes of a column (consumed).
    pub fn rest(&mut self, key: u32) -> Vec<u8> {
        match self.map.get_mut(&key) {
            Some(c) => {
                let v = c.data[c.pos..].to_vec();
                c.pos = c.data.len();
                v
            }
            None => Vec::new(),
        }
    }
    pub fn has(&self, key: u32) -> bool {
        self.map.contains_key(&key)
    }
}

// ---------------------------------------------------------------------------
// LZMA per column
// ---------------------------------------------------------------------------

fn lzma_options(level: u32, raw_len: usize) -> lzma_rust2::LzmaOptions {
    use lzma_rust2::{EncodeMode, MfType};
    let level = level.clamp(1, 9);
    let mut o = lzma_rust2::LzmaOptions::with_preset(level);
    // Dictionary never needs to exceed the input; rounding up to a power of
    // two keeps the decoder's memory predictable.
    let want = (raw_len.max(4096) as u64).next_power_of_two().min(1 << 30) as u32;
    o.dict_size = o.dict_size.min(want).max(4096);
    if level >= 8 {
        // "Extreme" settings: exhaustive match finding pays off on columns.
        o.mode = EncodeMode::Normal;
        o.mf = MfType::Bt4;
        o.nice_len = 273;
        o.depth_limit = 0;
    }
    o
}

fn compress_column(level: u32, raw: &[u8]) -> (u8, Vec<u8>) {
    if raw.len() < 64 {
        return (CODEC_RAW, raw.to_vec());
    }
    let opts = lzma_options(level, raw.len());
    let mut out = Vec::with_capacity(raw.len() / 4 + 64);
    let ok = (|| -> std::io::Result<()> {
        let mut w = lzma_rust2::LzmaWriter::new_use_header(&mut out, &opts, Some(raw.len() as u64))?;
        w.write_all(raw)?;
        w.finish()?;
        Ok(())
    })()
    .is_ok();
    if ok && out.len() < raw.len() {
        (CODEC_LZMA, out)
    } else {
        (CODEC_RAW, raw.to_vec())
    }
}

fn decompress_column(codec: u8, comp: &[u8], raw_len: u64) -> Result<Vec<u8>> {
    match codec {
        CODEC_RAW => Ok(comp.to_vec()),
        CODEC_LZMA => {
            let mut r = lzma_rust2::LzmaReader::new_mem_limit(comp, u32::MAX, None)
                .map_err(|e| PackError::Lzma(e.to_string()))?;
            let mut out = Vec::with_capacity(raw_len as usize);
            r.read_to_end(&mut out)
                .map_err(|e| PackError::Lzma(e.to_string()))?;
            if out.len() as u64 != raw_len {
                return fmt_err("column length mismatch after decompression");
            }
            Ok(out)
        }
        _ => fmt_err(format!("unknown column codec {codec}")),
    }
}

// ---------------------------------------------------------------------------
// Container writer / reader
// ---------------------------------------------------------------------------

/// Per-column accounting, aggregated over all blocks (for `pack --stats`).
#[derive(Debug, Default, Clone)]
pub struct ColStat {
    pub raw: u64,
    pub comp: u64,
}

type Columns = Vec<(u32, Vec<u8>)>;
type WriterResult<W> = Result<(W, HashMap<u32, ColStat>, u64, u64)>;
type Slot = std::sync::Mutex<Option<(u8, Vec<u8>)>>;

struct Job {
    seq: u64,
    items: u64,
    columns: Columns,
}

struct Done {
    seq: u64,
    items: u64,
    cols: Vec<(u32, Vec<u8>, u8, Vec<u8>)>, // key, raw (for stats len), codec, comp
}

/// Pipelined archive writer: blocks handed to `write_block` are compressed
/// by a pool of block workers (each parallel over its columns) and written
/// in order by a dedicated thread, so parsing never waits on LZMA.
pub struct Writer<W: Write + Send + 'static> {
    tx: Option<crossbeam_channel::Sender<Job>>,
    seq: u64,
    workers: Vec<std::thread::JoinHandle<()>>,
    writer: Option<std::thread::JoinHandle<WriterResult<W>>>,
}

impl<W: Write + Send + 'static> Writer<W> {
    pub fn new(mut out: W, kind: u8, opts: PackOptions) -> Result<Self> {
        out.write_all(MAGIC)?;
        out.write_all(&[VERSION, kind])?;
        let threads = opts.threads.max(1);
        // A few blocks in flight at once; each block worker fans out over
        // its columns with the remaining thread budget.
        let par_blocks = (threads / 6).clamp(1, 4);
        let per_block = (threads / par_blocks).max(1);
        let (tx, rx) = crossbeam_channel::bounded::<Job>(par_blocks);
        let (dtx, drx) = crossbeam_channel::unbounded::<Done>();
        let level = opts.level;
        let mut workers = Vec::new();
        for _ in 0..par_blocks {
            let rx = rx.clone();
            let dtx = dtx.clone();
            workers.push(std::thread::spawn(move || {
                while let Ok(job) = rx.recv() {
                    let done = compress_block(job, level, per_block);
                    if dtx.send(done).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(dtx);
        let writer = std::thread::spawn(move || -> WriterResult<W> {
            let mut stats: HashMap<u32, ColStat> = HashMap::new();
            let mut blocks = 0u64;
            let mut bytes_out = 6u64;
            let mut next = 0u64;
            let mut pending: HashMap<u64, Done> = HashMap::new();
            while let Ok(d) = drx.recv() {
                pending.insert(d.seq, d);
                while let Some(d) = pending.remove(&next) {
                    write_done(&mut out, &d, &mut stats, &mut bytes_out)?;
                    blocks += 1;
                    next += 1;
                }
            }
            out.write_all(&0u64.to_le_bytes())?;
            bytes_out += 8;
            out.flush()?;
            Ok((out, stats, blocks, bytes_out))
        });
        Ok(Writer {
            tx: Some(tx),
            seq: 0,
            workers,
            writer: Some(writer),
        })
    }

    /// Queue one block for compression. `items` is the logical item count
    /// (packets or lines) the block holds. Blocks whose columns are all
    /// empty are skipped.
    pub fn write_block(&mut self, items: u64, cols: &mut Cols) -> Result<()> {
        let columns = cols.take();
        if columns.is_empty() {
            return Ok(());
        }
        let job = Job { seq: self.seq, items, columns };
        self.seq += 1;
        match self.tx.as_ref().unwrap().send(job) {
            Ok(()) => Ok(()),
            Err(_) => self.join_err(),
        }
    }

    fn join_err(&mut self) -> Result<()> {
        // The writer thread died; surface its error.
        self.tx.take();
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        match self.writer.take().map(|h| h.join()) {
            Some(Ok(Err(e))) => Err(e),
            _ => fmt_err("archive writer thread failed"),
        }
    }

    /// Flush all queued blocks, write the end marker and return the output
    /// together with the per-column accounting.
    pub fn finish(mut self) -> Result<(W, Summary)> {
        self.tx.take();
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        let h = self.writer.take().unwrap();
        let (out, stats, blocks, bytes_out) = h
            .join()
            .map_err(|_| PackError::Format("archive writer thread panicked".into()))??;
        Ok((out, Summary { stats, blocks, bytes_out }))
    }
}

/// What an archive write produced.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub stats: HashMap<u32, ColStat>,
    pub blocks: u64,
    pub bytes_out: u64,
}

fn compress_block(job: Job, level: u32, threads: usize) -> Done {
    let columns = job.columns;
    // Biggest columns first so the tail of the fan-out is short.
    let mut order: Vec<usize> = (0..columns.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(columns[i].1.len()));
    let slots: Vec<Slot> = (0..columns.len()).map(|_| std::sync::Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads.min(columns.len()).max(1) {
            s.spawn(|| loop {
                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if k >= order.len() {
                    break;
                }
                let i = order[k];
                *slots[i].lock().unwrap() = Some(compress_column(level, &columns[i].1));
            });
        }
    });
    let cols = columns
        .into_iter()
        .zip(slots)
        .map(|((key, raw), slot)| {
            let (codec, comp) = slot.into_inner().unwrap().unwrap();
            (key, raw, codec, comp)
        })
        .collect();
    Done { seq: job.seq, items: job.items, cols }
}

fn write_done<W: Write>(
    out: &mut W,
    d: &Done,
    stats: &mut HashMap<u32, ColStat>,
    bytes_out: &mut u64,
) -> Result<()> {
    let mut hdr = Vec::with_capacity(12);
    hdr.extend_from_slice(&d.items.to_le_bytes());
    hdr.extend_from_slice(&(d.cols.len() as u32).to_le_bytes());
    out.write_all(&hdr)?;
    *bytes_out += hdr.len() as u64;
    for (key, raw, codec, comp) in &d.cols {
        let mut h = Vec::with_capacity(21);
        h.extend_from_slice(&key.to_le_bytes());
        h.push(*codec);
        h.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        h.extend_from_slice(&(comp.len() as u64).to_le_bytes());
        out.write_all(&h)?;
        out.write_all(comp)?;
        *bytes_out += (h.len() + comp.len()) as u64;
        let st = stats.entry(*key).or_default();
        st.raw += raw.len() as u64;
        st.comp += (comp.len() + h.len()) as u64;
    }
    Ok(())
}

pub struct Reader<R: Read> {
    inp: R,
    pub kind: u8,
}

impl<R: Read> Reader<R> {
    pub fn new(mut inp: R) -> Result<Self> {
        let mut h = [0u8; 6];
        inp.read_exact(&mut h)?;
        if &h[..4] != MAGIC {
            return fmt_err("not a .lwz archive (bad magic)");
        }
        if h[4] != VERSION {
            return fmt_err(format!("unsupported .lwz version {}", h[4]));
        }
        Ok(Reader { inp, kind: h[5] })
    }

    /// Read and decompress the next block; `None` at end of archive.
    pub fn next_block(&mut self) -> Result<Option<(u64, ColReaders)>> {
        let mut b8 = [0u8; 8];
        self.inp.read_exact(&mut b8)?;
        let items = u64::from_le_bytes(b8);
        if items == 0 {
            return Ok(None);
        }
        let mut b4 = [0u8; 4];
        self.inp.read_exact(&mut b4)?;
        let ncols = u32::from_le_bytes(b4) as usize;
        let mut raw_cols: Vec<(u32, u8, u64, Vec<u8>)> = Vec::with_capacity(ncols);
        for _ in 0..ncols {
            let mut h = [0u8; 21];
            self.inp.read_exact(&mut h)?;
            let key = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let codec = h[4];
            let raw_len = u64::from_le_bytes(h[5..13].try_into().unwrap());
            let comp_len = u64::from_le_bytes(h[13..21].try_into().unwrap());
            let mut comp = vec![0u8; comp_len as usize];
            self.inp.read_exact(&mut comp)?;
            raw_cols.push((key, codec, raw_len, comp));
        }
        // Decompress in parallel.
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(raw_cols.len().max(1));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<Result<Vec<u8>>>>> =
            (0..raw_cols.len()).map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= raw_cols.len() {
                        break;
                    }
                    let (_, codec, raw_len, comp) = &raw_cols[i];
                    let r = decompress_column(*codec, comp, *raw_len);
                    *slots[i].lock().unwrap() = Some(r);
                });
            }
        });
        let mut cols = ColReaders::default();
        for (i, slot) in slots.into_iter().enumerate() {
            let data = slot.into_inner().unwrap().unwrap()?;
            cols.map.insert(raw_cols[i].0, Cursor { data, pos: 0 });
        }
        Ok(Some((items, cols)))
    }
}

/// Human-readable name for a column key (for `--stats`).
pub fn col_name(key: u32) -> String {
    if let Some(n) = packet::col_name(key) {
        return n;
    }
    if let Some(n) = pcap::col_name(key) {
        return n;
    }
    if let Some(n) = jsonl::col_name(key) {
        return n;
    }
    format!("col{key:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0i64, 1, -1, 127, -128, 1 << 40, -(1 << 40), i64::MAX, i64::MIN] {
            let mut b = Vec::new();
            put_varint(&mut b, zigzag(v));
            let mut c = Cols::default();
            c.bytes(1, &b);
            let mut r = ColReaders::default();
            r.map.insert(1, Cursor { data: b, pos: 0 });
            assert_eq!(r.zig(1).unwrap(), v);
        }
    }

    #[test]
    fn column_codec_roundtrip() {
        let raw: Vec<u8> = (0..50_000u32).map(|i| (i % 7) as u8).collect();
        let (codec, comp) = compress_column(6, &raw);
        assert_eq!(codec, CODEC_LZMA);
        assert!(comp.len() < raw.len() / 10);
        assert_eq!(decompress_column(codec, &comp, raw.len() as u64).unwrap(), raw);
    }
}

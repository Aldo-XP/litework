//! The `.lwix` sidecar: persisted index next to the capture. One build pass
//! writes tier-0 summaries, global stats, and lz4-compressed per-group packet
//! columns; reopening the capture later loads in milliseconds and every query
//! runs off the columns without touching the pcap.
//!
//! Layout:  [header 96B] [group column blocks...] [lz4 footer]
//! The footer carries groups/dicts/stats; the header records the source file's
//! size + first-64K hash so a changed capture invalidates the sidecar.

use crate::columns::GroupColumns;
use crate::format::{NgSnapshot, PcapFile};
use crate::hist::{TimeHist, HIST_BUCKETS};
use crate::index::{CaptureIndex, ConvStat, GlobalStats, IpDict, MacDict, MacStat, RowGroup};
use crate::sketch::{Bloom, CappedSet, ProtoBits};
use crate::types::ProtoKey;
use ahash::{AHashMap, RandomState};
use memmap2::Mmap;
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"LWIX0001";
const HEADER_LEN: u64 = 96;

/// Default sidecar location: `<capture>.lwix` next to the capture.
pub fn sidecar_path(capture: &Path) -> PathBuf {
    let mut os = capture.as_os_str().to_owned();
    os.push(".lwix");
    PathBuf::from(os)
}

/// Stable hash of the capture's first 64 KB + length, for invalidation.
pub fn source_hash(file: &PcapFile) -> (u64, u64) {
    let head_rec = crate::types::PacketRecord {
        ts_nanos: 0,
        record_offset: 0,
        data_offset: 0,
        caplen: file.len().min(65_536) as u32,
        origlen: 0,
        linktype: 0,
    };
    let head = file.bytes(&head_rec);
    let h1 = RandomState::with_seeds(1, 2, 3, 4).hash_one(head);
    let h2 = RandomState::with_seeds(5, 6, 7, 8).hash_one(head);
    (h1, h2)
}

// ------------------------------------------------------------ byte helpers

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub struct CorruptSidecar;

impl<'a> R<'a> {
    fn u8(&mut self) -> Result<u8, CorruptSidecar> {
        let v = *self.b.get(self.pos).ok_or(CorruptSidecar)?;
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, CorruptSidecar> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, CorruptSidecar> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CorruptSidecar> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CorruptSidecar> {
        let s = self.b.get(self.pos..self.pos + n).ok_or(CorruptSidecar)?;
        self.pos += n;
        Ok(s)
    }
}

fn w_capped(w: &mut W, s: &CappedSet) {
    w.u8(s.is_overflowed() as u8);
    w.u32(s.len() as u32);
    for v in s.iter() {
        w.u32(v);
    }
}

fn r_capped(r: &mut R) -> Result<CappedSet, CorruptSidecar> {
    let overflow = r.u8()? != 0;
    let n = r.u32()? as usize;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        items.push(r.u32()?);
    }
    Ok(CappedSet::from_parts(items, overflow))
}

fn w_proto(w: &mut W, p: &ProtoKey) {
    match p {
        ProtoKey::Ip(v) => {
            w.u8(0);
            w.u16(*v as u16);
        }
        ProtoKey::Ether(v) => {
            w.u8(1);
            w.u16(*v);
        }
        ProtoKey::Other => {
            w.u8(2);
            w.u16(0);
        }
    }
}

fn r_proto(r: &mut R) -> Result<ProtoKey, CorruptSidecar> {
    let tag = r.u8()?;
    let v = r.u16()?;
    Ok(match tag {
        0 => ProtoKey::Ip(v as u8),
        1 => ProtoKey::Ether(v),
        _ => ProtoKey::Other,
    })
}

// ------------------------------------------------------------ writer

pub struct SidecarWriter {
    file: File,
    pos: u64,
}

impl SidecarWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(&[0u8; HEADER_LEN as usize])?;
        Ok(SidecarWriter {
            file,
            pos: HEADER_LEN,
        })
    }

    /// Compress and append one group's raw column bytes.
    pub fn append_block(&mut self, raw: &[u8]) -> io::Result<(u64, u32, u32)> {
        let comp = lz4_flex::compress_prepend_size(raw);
        let off = self.pos;
        self.file.write_all(&comp)?;
        self.pos += comp.len() as u64;
        Ok((off, comp.len() as u32, raw.len() as u32))
    }

    /// Write the footer + header and close.
    pub fn finish(mut self, file: &PcapFile, index: &CaptureIndexParts) -> io::Result<()> {
        let mut w = W(Vec::with_capacity(1 << 20));
        // 1. groups
        w.u32(index.groups.len() as u32);
        for g in index.groups {
            w.u64(g.first_pkt);
            w.u32(g.pkt_count);
            w.u64(g.first_ts);
            w.u64(g.last_ts);
            w.u64(g.byte_count);
            w.u64(g.start_offset);
            let (off, comp, raw) = g.block.unwrap_or((0, 0, 0));
            w.u64(off);
            w.u32(comp);
            w.u32(raw);
            w_capped(&mut w, &g.macs);
            w_capped(&mut w, &g.ethertypes);
            for x in g.ipprotos.0 {
                w.u64(x);
            }
            w.bytes(g.port_bloom.as_bytes());
            w.bytes(g.ip_bloom.as_bytes());
        }
        // 2. mac dict
        w.u32(index.dict.len() as u32);
        for i in 0..index.dict.len() {
            w.bytes(&index.dict.get(i as u32));
        }
        // 3. ip dict
        w.u32(index.ip_dict.len() as u32);
        for i in 0..index.ip_dict.len() {
            let (kind, bytes) = index.ip_dict.get(i as u32);
            w.u8(kind);
            w.bytes(&bytes);
        }
        // 4. ng checkpoints
        w.u32(index.ng_checkpoints.len() as u32);
        for (off, snap) in index.ng_checkpoints {
            w.u64(*off);
            w.u8(snap.bigendian as u8);
            w.u32(snap.ifaces.len() as u32);
            for (lt, tps) in &snap.ifaces {
                w.u16(*lt);
                w.u64(*tps);
            }
        }
        // 5. stats
        let s = index.stats;
        w.u64(s.packets);
        w.u64(s.bytes);
        w.u64(s.first_ts);
        w.u64(s.last_ts);
        w.u32(s.protos.len() as u32);
        for (k, (p, b)) in &s.protos {
            w_proto(&mut w, k);
            w.u64(*p);
            w.u64(*b);
        }
        w.u32(s.macs.len() as u32);
        for (id, m) in &s.macs {
            w.u32(*id);
            w.u64(m.pkts);
            w.u64(m.bytes);
            w.u64(m.first_ts);
            w.u64(m.last_ts);
            w.u16(m.protos.len() as u16);
            for p in &m.protos {
                w_proto(&mut w, p);
            }
        }
        for c in s.ports.iter() {
            w.u64(*c);
        }
        w.u64(s.hist.width_nanos());
        w.u64(s.hist.origin_nanos());
        for c in s.hist.counts() {
            w.u64(*c);
        }
        for b in s.hist.bytes() {
            w.u64(*b);
        }
        // 6. conversations
        w.u32(s.convs.len() as u32);
        for ((a, b), c) in &s.convs {
            w.u32(*a);
            w.u32(*b);
            w.u64(c.pkts);
            w.u64(c.bytes);
            w.u64(c.first_ts);
            w.u64(c.last_ts);
            w.u16(c.protos.len() as u16);
            for p in &c.protos {
                w_proto(&mut w, p);
            }
            w_capped(&mut w, &c.ports);
        }
        w.u64(s.convs_overflow);
        // 7. truncated
        w.u8(*index.truncated as u8);

        let comp = lz4_flex::compress_prepend_size(&w.0);
        let footer_off = self.pos;
        self.file.write_all(&comp)?;

        // header
        let (h1, h2) = source_hash(file);
        let mut hdr = W(Vec::with_capacity(HEADER_LEN as usize));
        hdr.bytes(MAGIC);
        hdr.u32(1); // version
        hdr.u64(file.len());
        hdr.u64(h1);
        hdr.u64(h2);
        hdr.u64(index.stats.packets);
        hdr.u32(index.groups.len() as u32);
        hdr.u64(footer_off);
        hdr.u64(comp.len() as u64);
        hdr.0.resize(HEADER_LEN as usize, 0);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&hdr.0)?;
        self.file.flush()?;
        Ok(())
    }
}

/// Borrowed view of the index pieces the writer serializes.
pub struct CaptureIndexParts<'a> {
    pub groups: &'a [RowGroup],
    pub dict: &'a MacDict,
    pub ip_dict: &'a IpDict,
    pub ng_checkpoints: &'a [(u64, NgSnapshot)],
    pub stats: &'a GlobalStats,
    pub truncated: &'a bool,
}

// ------------------------------------------------------------ runtime store

/// Open sidecar: mmap'd blocks + a bounded cache of decompressed groups.
pub struct Sidecar {
    mmap: Mmap,
    blocks: Vec<(u64, u32, u32)>,
    cache: Mutex<Cache>,
}

struct Cache {
    map: AHashMap<usize, Arc<GroupColumns>>,
    order: VecDeque<usize>,
    bytes: usize,
    limit: usize,
}

impl Sidecar {
    /// Decompressed columns for group `gi`, cached under the memory budget.
    pub fn group(&self, gi: usize) -> Option<Arc<GroupColumns>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(c) = cache.map.get(&gi) {
                return Some(c.clone());
            }
        }
        let (off, comp, _raw) = *self.blocks.get(gi)?;
        let slice = self.mmap.get(off as usize..off as usize + comp as usize)?;
        let raw = lz4_flex::decompress_size_prepended(slice).ok()?;
        // Return the mmap'd pages once decoded — keeps RSS at the cache
        // budget instead of cache + sidecar file size.
        #[cfg(unix)]
        {
            let page = 4096usize;
            let a = (off as usize) & !(page - 1);
            let end = (off as usize + comp as usize) & !(page - 1);
            if end > a {
                // Safety: read-only file-backed map; DONTNEED drops clean pages.
                unsafe {
                    let _ = self.mmap.unchecked_advise_range(
                        memmap2::UncheckedAdvice::DontNeed,
                        a,
                        end - a,
                    );
                }
            }
        }
        let cols = Arc::new(GroupColumns::decode(&raw)?);
        let mut cache = self.cache.lock().unwrap();
        let sz = cols.approx_bytes();
        while cache.bytes + sz > cache.limit && !cache.order.is_empty() {
            if let Some(old) = cache.order.pop_front() {
                if let Some(c) = cache.map.remove(&old) {
                    cache.bytes -= c.approx_bytes();
                }
            }
        }
        cache.bytes += sz;
        cache.order.push_back(gi);
        cache.map.insert(gi, cols.clone());
        Some(cols)
    }

    pub fn cached_bytes(&self) -> usize {
        self.cache.lock().unwrap().bytes
    }
}

/// Try to load a valid sidecar for `file`. Returns None when missing, stale,
/// or corrupt (callers rebuild in that case).
pub fn load(path: &Path, file: &PcapFile, mem_limit: usize) -> Option<CaptureIndex> {
    let t0 = std::time::Instant::now();
    let f = File::open(path).ok()?;
    let mmap = unsafe { Mmap::map(&f).ok()? };
    if mmap.len() < HEADER_LEN as usize || &mmap[0..8] != MAGIC {
        return None;
    }
    let mut hr = R { b: &mmap, pos: 8 };
    let version = hr.u32().ok()?;
    if version != 1 {
        return None;
    }
    let src_size = hr.u64().ok()?;
    let h1 = hr.u64().ok()?;
    let h2 = hr.u64().ok()?;
    if src_size != file.len() || (h1, h2) != source_hash(file) {
        return None; // capture changed — stale index
    }
    let _packets = hr.u64().ok()?;
    let group_count = hr.u32().ok()? as usize;
    let footer_off = hr.u64().ok()? as usize;
    let footer_len = hr.u64().ok()? as usize;

    let comp = mmap.get(footer_off..footer_off + footer_len)?;
    let raw = lz4_flex::decompress_size_prepended(comp).ok()?;
    let mut r = R { b: &raw, pos: 0 };
    parse_footer(&mut r, group_count, mmap, mem_limit, t0).ok()
}

fn parse_footer(
    r: &mut R,
    group_count: usize,
    mmap: Mmap,
    mem_limit: usize,
    t0: std::time::Instant,
) -> Result<CaptureIndex, CorruptSidecar> {
    // 1. groups
    let n = r.u32()? as usize;
    if n != group_count {
        return Err(CorruptSidecar);
    }
    let mut groups = Vec::with_capacity(n);
    let mut blocks = Vec::with_capacity(n);
    for _ in 0..n {
        let first_pkt = r.u64()?;
        let pkt_count = r.u32()?;
        let first_ts = r.u64()?;
        let last_ts = r.u64()?;
        let byte_count = r.u64()?;
        let start_offset = r.u64()?;
        let block = (r.u64()?, r.u32()?, r.u32()?);
        let macs = r_capped(r)?;
        let ethertypes = r_capped(r)?;
        let mut ipprotos = ProtoBits::default();
        for x in ipprotos.0.iter_mut() {
            *x = r.u64()?;
        }
        let port_bloom = Bloom::from_bytes(r.take(512)?.try_into().unwrap());
        let ip_bloom = Bloom::from_bytes(r.take(1024)?.try_into().unwrap());
        blocks.push(block);
        groups.push(RowGroup {
            first_pkt,
            pkt_count,
            first_ts,
            last_ts,
            byte_count,
            start_offset,
            block: Some(block),
            macs,
            ethertypes,
            ipprotos,
            port_bloom,
            ip_bloom,
        });
    }
    // 2. mac dict
    let n = r.u32()? as usize;
    let mut dict = MacDict::default();
    for _ in 0..n {
        dict.intern(r.take(6)?.try_into().unwrap());
    }
    // 3. ip dict
    let n = r.u32()? as usize;
    let mut ip_dict = IpDict::default();
    for _ in 0..n {
        let kind = r.u8()?;
        let bytes: [u8; 16] = r.take(16)?.try_into().unwrap();
        ip_dict.intern_raw(kind, bytes);
    }
    // 4. checkpoints
    let n = r.u32()? as usize;
    let mut ng_checkpoints = Vec::with_capacity(n);
    for _ in 0..n {
        let off = r.u64()?;
        let bigendian = r.u8()? != 0;
        let ni = r.u32()? as usize;
        let mut ifaces = Vec::with_capacity(ni);
        for _ in 0..ni {
            ifaces.push((r.u16()?, r.u64()?));
        }
        ng_checkpoints.push((off, NgSnapshot { bigendian, ifaces }));
    }
    // 5. stats
    let mut stats = GlobalStats {
        packets: r.u64()?,
        bytes: r.u64()?,
        first_ts: r.u64()?,
        last_ts: r.u64()?,
        ..Default::default()
    };
    let n = r.u32()? as usize;
    for _ in 0..n {
        let k = r_proto(r)?;
        let p = r.u64()?;
        let b = r.u64()?;
        stats.protos.insert(k, (p, b));
    }
    let n = r.u32()? as usize;
    for _ in 0..n {
        let id = r.u32()?;
        let mut m = MacStat {
            pkts: r.u64()?,
            bytes: r.u64()?,
            first_ts: r.u64()?,
            last_ts: r.u64()?,
            protos: BTreeSet::new(),
        };
        let np = r.u16()? as usize;
        for _ in 0..np {
            m.protos.insert(r_proto(r)?);
        }
        stats.macs.insert(id, m);
    }
    for c in stats.ports.iter_mut() {
        *c = r.u64()?;
    }
    let width = r.u64()?;
    let origin = r.u64()?;
    let mut counts = vec![0u64; HIST_BUCKETS];
    let mut hbytes = vec![0u64; HIST_BUCKETS];
    for c in counts.iter_mut() {
        *c = r.u64()?;
    }
    for b in hbytes.iter_mut() {
        *b = r.u64()?;
    }
    stats.hist = TimeHist::from_parts(width, origin, counts, hbytes);
    // 6. conversations
    let n = r.u32()? as usize;
    for _ in 0..n {
        let a = r.u32()?;
        let b = r.u32()?;
        let mut c = ConvStat {
            pkts: r.u64()?,
            bytes: r.u64()?,
            first_ts: r.u64()?,
            last_ts: r.u64()?,
            protos: BTreeSet::new(),
            ports: CappedSet::default(),
        };
        let np = r.u16()? as usize;
        for _ in 0..np {
            c.protos.insert(r_proto(r)?);
        }
        c.ports = r_capped(r)?;
        stats.convs.insert((a, b), c);
    }
    stats.convs_overflow = r.u64()?;
    // 7
    let truncated = r.u8()? != 0;

    Ok(CaptureIndex {
        dict,
        ip_dict,
        groups,
        stats,
        ng_checkpoints,
        truncated,
        build_millis: t0.elapsed().as_millis() as u64,
        loaded_from_sidecar: true,
        warning: None,
        sidecar: Some(Sidecar {
            mmap,
            blocks,
            cache: Mutex::new(Cache {
                map: AHashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                limit: mem_limit.max(8 << 20),
            }),
        }),
    })
}

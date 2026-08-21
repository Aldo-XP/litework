//! Tier-0 index + tier-1 columns, built in a single sequential pass. Tier-0
//! (row-group summaries, global stats) answers "which regions could match";
//! tier-1 (per-packet columns, persisted in the `.lwix` sidecar) makes every
//! later query and packet-list scroll run without touching the capture.

use crate::columns::GroupColumns;
use crate::dissect::dissect;
use crate::format::{Event, FormatError, NgSnapshot, PcapFile};
use crate::hist::TimeHist;
use crate::sidecar::{self, CaptureIndexParts, Sidecar, SidecarWriter};
use crate::sketch::{Bloom, CappedSet, ProtoBits};
use crate::types::*;
use ahash::AHashMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

/// Packets per row group. 64K packets ≈ 8 KB of tier-0 summary; a 500 GB /
/// ~715 M packet capture yields ~11 K groups ≈ under 100 MB resident.
pub const ROW_GROUP_SIZE: u32 = 65_536;

/// Conversation-table cap: beyond this many distinct IP pairs, new pairs are
/// counted in `convs_overflow` instead of tracked individually.
pub const CONV_CAP: usize = 262_144;

/// Interned MAC addresses. MAC cardinality on real networks is small
/// (thousands), so ids are dense u32s used everywhere else.
#[derive(Default)]
pub struct MacDict {
    map: AHashMap<[u8; 6], u32>,
    macs: Vec<[u8; 6]>,
}

impl MacDict {
    pub fn intern(&mut self, mac: [u8; 6]) -> u32 {
        *self.map.entry(mac).or_insert_with(|| {
            self.macs.push(mac);
            (self.macs.len() - 1) as u32
        })
    }
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<u32> {
        self.map.get(mac).copied()
    }
    pub fn get(&self, id: u32) -> [u8; 6] {
        self.macs[id as usize]
    }
    pub fn len(&self) -> usize {
        self.macs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.macs.is_empty()
    }
}

/// Interned IP addresses (v4 and v6), used by columns and conversations.
#[derive(Default)]
pub struct IpDict {
    map: AHashMap<[u8; 17], u32>,
    addrs: Vec<[u8; 17]>, // kind byte (4|6) + 16 address bytes
}

impl IpDict {
    fn intern_key(&mut self, key: [u8; 17]) -> u32 {
        *self.map.entry(key).or_insert_with(|| {
            self.addrs.push(key);
            (self.addrs.len() - 1) as u32
        })
    }
    pub fn intern_v4(&mut self, a: [u8; 4]) -> u32 {
        let mut key = [0u8; 17];
        key[0] = 4;
        key[1..5].copy_from_slice(&a);
        self.intern_key(key)
    }
    pub fn intern_v6(&mut self, a: [u8; 16]) -> u32 {
        let mut key = [0u8; 17];
        key[0] = 6;
        key[1..17].copy_from_slice(&a);
        self.intern_key(key)
    }
    /// Re-intern from persisted (kind, bytes) — sidecar load path.
    pub fn intern_raw(&mut self, kind: u8, bytes: [u8; 16]) -> u32 {
        let mut key = [0u8; 17];
        key[0] = kind;
        key[1..17].copy_from_slice(&bytes);
        self.intern_key(key)
    }
    pub fn get(&self, id: u32) -> (u8, [u8; 16]) {
        let k = &self.addrs[id as usize];
        (k[0], k[1..17].try_into().unwrap())
    }
    /// NetAddrs for a (src, dst) id pair (kinds always agree within a packet).
    pub fn net_addrs(&self, src: u32, dst: u32) -> NetAddrs {
        let (ks, s) = self.get(src);
        let (_, d) = self.get(dst);
        if ks == 4 {
            NetAddrs::V4 {
                src: s[0..4].try_into().unwrap(),
                dst: d[0..4].try_into().unwrap(),
            }
        } else {
            NetAddrs::V6 { src: s, dst: d }
        }
    }
    pub fn fmt(&self, id: u32) -> String {
        let (kind, b) = self.get(id);
        if kind == 4 {
            std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
        } else {
            std::net::Ipv6Addr::from(b).to_string()
        }
    }
    pub fn len(&self) -> usize {
        self.addrs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

/// Summary of one contiguous run of `ROW_GROUP_SIZE` packets.
pub struct RowGroup {
    /// Index of the first packet in this group (0-based over the capture).
    pub first_pkt: u64,
    pub pkt_count: u32,
    pub first_ts: u64,
    pub last_ts: u64,
    pub byte_count: u64,
    /// Record-boundary offset where this group starts — rescans resume here.
    pub start_offset: u64,
    /// Sidecar column block (offset, compressed len, raw len), when present.
    pub block: Option<(u64, u32, u32)>,
    /// MAC dictionary ids seen (capped, degrades to maybe-any).
    pub macs: CappedSet,
    /// Ethertypes seen (stored as u32 in a capped set).
    pub ethertypes: CappedSet,
    /// IP protocol numbers seen.
    pub ipprotos: ProtoBits,
    /// TCP/UDP ports seen (src+dst).
    pub port_bloom: Bloom<512>,
    /// IPv4/IPv6 addresses seen (src+dst).
    pub ip_bloom: Bloom<1024>,
}

impl RowGroup {
    fn new(first_pkt: u64, start_offset: u64) -> Self {
        RowGroup {
            first_pkt,
            pkt_count: 0,
            first_ts: u64::MAX,
            last_ts: 0,
            byte_count: 0,
            start_offset,
            block: None,
            macs: CappedSet::default(),
            ethertypes: CappedSet::default(),
            ipprotos: ProtoBits::default(),
            port_bloom: Bloom::new(),
            ip_bloom: Bloom::new(),
        }
    }
}

/// Per-MAC aggregate: the core "what does this device speak" correlation.
#[derive(Default, Clone)]
pub struct MacStat {
    pub pkts: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub protos: BTreeSet<ProtoKey>,
}

/// One IP⇄IP conversation (both directions folded together).
#[derive(Default, Clone)]
pub struct ConvStat {
    pub pkts: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub protos: BTreeSet<ProtoKey>,
    /// Ports observed on either side (capped).
    pub ports: CappedSet,
}

/// Whole-capture aggregates computed during the scan.
pub struct GlobalStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub protos: AHashMap<ProtoKey, (u64, u64)>, // (pkts, bytes)
    pub macs: AHashMap<u32, MacStat>,
    /// Packet count per TCP/UDP port (src or dst).
    pub ports: Vec<u64>, // len 65536
    pub hist: TimeHist,
    /// IP⇄IP conversations keyed by normalized (min_id, max_id).
    pub convs: AHashMap<(u32, u32), ConvStat>,
    pub convs_overflow: u64,
}

impl Default for GlobalStats {
    fn default() -> Self {
        GlobalStats {
            packets: 0,
            bytes: 0,
            first_ts: u64::MAX,
            last_ts: 0,
            protos: AHashMap::new(),
            macs: AHashMap::new(),
            ports: vec![0; 65_536],
            hist: TimeHist::new(),
            convs: AHashMap::new(),
            convs_overflow: 0,
        }
    }
}

impl GlobalStats {
    /// Protocols sorted by packet count: (proto, pkts, bytes).
    pub fn top_protos(&self) -> Vec<(ProtoKey, u64, u64)> {
        let mut v: Vec<_> = self.protos.iter().map(|(k, (p, b))| (*k, *p, *b)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v
    }

    /// MAC ids sorted by packet count.
    pub fn top_macs(&self) -> Vec<(u32, &MacStat)> {
        let mut v: Vec<_> = self.macs.iter().map(|(id, s)| (*id, s)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1.pkts));
        v
    }

    /// Busiest TCP/UDP ports: (port, pkts).
    pub fn top_ports(&self, n: usize) -> Vec<(u16, u64)> {
        let mut v: Vec<(u16, u64)> = self
            .ports
            .iter()
            .enumerate()
            .filter(|(_, &c)| c > 0)
            .map(|(p, &c)| (p as u16, c))
            .collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(n);
        v
    }

    /// All active ports sorted by packet count (for the scrollable PORTS tab).
    pub fn all_ports(&self) -> Vec<(u16, u64)> {
        self.top_ports(usize::MAX)
    }

    /// Conversations sorted by bytes.
    pub fn top_convs(&self) -> Vec<((u32, u32), &ConvStat)> {
        let mut v: Vec<_> = self.convs.iter().map(|(k, c)| (*k, c)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1.bytes));
        v
    }
}

/// How to open/build an index.
pub struct OpenOptions {
    /// Sidecar location: loaded from when present and valid. None disables
    /// sidecar use entirely.
    pub sidecar: Option<PathBuf>,
    /// Write the sidecar when building. Off by default so opening a capture
    /// leaves no files behind; opt in for instant reopens + column queries.
    pub persist: bool,
    /// Budget for decompressed column blocks kept in RAM.
    pub mem_limit_bytes: usize,
    /// Ignore any existing sidecar and rebuild from the capture.
    pub force_rebuild: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions {
            sidecar: None,
            persist: false,
            mem_limit_bytes: 512 << 20,
            force_rebuild: false,
        }
    }
}

impl OpenOptions {
    /// Load-or-build with persistence — used by tests and `litework index`.
    pub fn for_capture(file: &PcapFile) -> Self {
        OpenOptions {
            sidecar: Some(sidecar::sidecar_path(&file.path)),
            persist: true,
            ..Default::default()
        }
    }
}

/// The index over one capture file.
pub struct CaptureIndex {
    pub dict: MacDict,
    pub ip_dict: IpDict,
    pub groups: Vec<RowGroup>,
    pub stats: GlobalStats,
    /// pcapng section-state checkpoints: (group start offset, snapshot).
    /// Empty for legacy pcap.
    pub ng_checkpoints: Vec<(u64, NgSnapshot)>,
    pub truncated: bool,
    /// Time to build — or to load, when `loaded_from_sidecar`.
    pub build_millis: u64,
    pub loaded_from_sidecar: bool,
    /// Non-fatal problem during open (e.g. sidecar not writable).
    pub warning: Option<String>,
    pub sidecar: Option<Sidecar>,
}

impl CaptureIndex {
    /// Open the index for a capture: load a valid sidecar if one exists,
    /// otherwise scan the capture (persisting the sidecar when requested).
    pub fn open(
        file: &PcapFile,
        opts: &OpenOptions,
        progress: impl FnMut(u64, u64),
    ) -> Result<Self, FormatError> {
        if !opts.force_rebuild {
            if let Some(p) = &opts.sidecar {
                if let Some(idx) = sidecar::load(p, file, opts.mem_limit_bytes) {
                    return Ok(idx);
                }
            }
        }
        Self::build(file, opts, progress)
    }

    /// Compatibility entry point: in-memory tier-0 build, no sidecar.
    pub fn build_in_memory(
        file: &PcapFile,
        progress: impl FnMut(u64, u64),
    ) -> Result<Self, FormatError> {
        Self::build(file, &OpenOptions::default(), progress)
    }

    fn build(
        file: &PcapFile,
        opts: &OpenOptions,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<Self, FormatError> {
        let t0 = std::time::Instant::now();
        let total = file.len();
        let mut b = Builder {
            dict: MacDict::default(),
            ip_dict: IpDict::default(),
            groups: Vec::new(),
            stats: GlobalStats::default(),
            ng_checkpoints: Vec::new(),
            latest_snap: NgSnapshot::default(),
            cur: None,
            cols: GroupColumns::default(),
            writer: None,
            warning: None,
        };
        if opts.persist {
            if let Some(p) = &opts.sidecar {
                match SidecarWriter::create(p) {
                    Ok(w) => b.writer = Some(w),
                    Err(e) => {
                        b.warning = Some(format!(
                            "cannot write index sidecar {} ({e}); running without persistence",
                            p.display()
                        ))
                    }
                }
            }
        }
        let mut dropped_to: u64 = 0;

        file.advise_sequential();
        let report = file.for_each_event(file.first_packet_offset(), None, |ev| {
            match ev {
                Event::NgState(_, snap) => b.latest_snap = snap,
                Event::Packet(rec, data) => {
                    if b.group_full() {
                        b.close_group();
                        progress(rec.record_offset, total);
                        // Keep RSS flat: release pages behind the scan.
                        file.drop_pages(dropped_to, rec.record_offset - dropped_to);
                        dropped_to = rec.record_offset;
                    }
                    b.on_packet(&rec, data);
                }
            }
            true
        })?;
        b.close_group();
        progress(total, total);
        file.drop_pages(dropped_to, total - dropped_to);
        file.advise_random(); // subsequent access is point lookups

        // Legacy pcap needs no snapshots; drop the placeholder entries.
        if matches!(file.format, crate::format::CaptureFormat::Pcap { .. }) {
            b.ng_checkpoints.clear();
        }

        let mut warning = b.warning.take();
        let wrote_sidecar = b.writer.is_some();
        if let Some(w) = b.writer.take() {
            let parts = CaptureIndexParts {
                groups: &b.groups,
                dict: &b.dict,
                ip_dict: &b.ip_dict,
                ng_checkpoints: &b.ng_checkpoints,
                stats: &b.stats,
                truncated: &report.truncated,
            };
            if let Err(e) = w.finish(file, &parts) {
                warning = Some(format!("failed to finalize sidecar: {e}"));
            }
        }

        // Reload the just-written sidecar to get the runtime column store
        // (also verifies the roundtrip).
        let mut sidecar_rt = None;
        if wrote_sidecar && warning.is_none() {
            if let Some(p) = &opts.sidecar {
                match sidecar::load(p, file, opts.mem_limit_bytes) {
                    Some(idx) => sidecar_rt = idx.sidecar,
                    None => warning = Some("sidecar verification failed after write".into()),
                }
            }
        }

        Ok(CaptureIndex {
            dict: b.dict,
            ip_dict: b.ip_dict,
            groups: b.groups,
            stats: b.stats,
            ng_checkpoints: b.ng_checkpoints,
            truncated: report.truncated,
            build_millis: t0.elapsed().as_millis() as u64,
            loaded_from_sidecar: false,
            warning,
            sidecar: sidecar_rt,
        })
    }

    /// Decompressed columns for a group (sidecar-backed; None without one).
    pub fn group_columns(&self, gi: usize) -> Option<Arc<GroupColumns>> {
        self.sidecar.as_ref()?.group(gi)
    }

    /// Latest pcapng snapshot at or before `offset` (None for legacy pcap).
    pub fn snapshot_for(&self, offset: u64) -> Option<&NgSnapshot> {
        match self
            .ng_checkpoints
            .binary_search_by_key(&offset, |(o, _)| *o)
        {
            Ok(i) => Some(&self.ng_checkpoints[i].1),
            Err(0) => None,
            Err(i) => Some(&self.ng_checkpoints[i - 1].1),
        }
    }
}

struct Builder {
    dict: MacDict,
    ip_dict: IpDict,
    groups: Vec<RowGroup>,
    stats: GlobalStats,
    ng_checkpoints: Vec<(u64, NgSnapshot)>,
    latest_snap: NgSnapshot,
    cur: Option<RowGroup>,
    cols: GroupColumns,
    writer: Option<SidecarWriter>,
    warning: Option<String>,
}

impl Builder {
    fn group_full(&self) -> bool {
        match &self.cur {
            Some(g) => g.pkt_count >= ROW_GROUP_SIZE,
            None => true,
        }
    }

    fn close_group(&mut self) {
        if let Some(mut g) = self.cur.take() {
            if let Some(w) = &mut self.writer {
                let raw = self.cols.encode();
                match w.append_block(&raw) {
                    Ok(block) => g.block = Some(block),
                    Err(e) => {
                        self.warning = Some(format!("sidecar write failed: {e}"));
                        self.writer = None;
                    }
                }
            }
            self.cols = GroupColumns::default();
            self.groups.push(g);
        }
    }

    fn on_packet(&mut self, rec: &PacketRecord, data: &[u8]) {
        if self.cur.is_none() {
            self.ng_checkpoints
                .push((rec.record_offset, self.latest_snap.clone()));
            self.cur = Some(RowGroup::new(self.stats.packets, rec.record_offset));
        }
        let meta = dissect(rec.linktype, data);
        // --- columns (tier-1) ---
        if self.writer.is_some() {
            self.cols.push(rec, &meta, &mut self.dict, &mut self.ip_dict);
        }
        ingest_packet_stats(
            self.cur.as_mut().unwrap(),
            &mut self.stats,
            &mut self.dict,
            &mut self.ip_dict,
            rec,
            &meta,
        );
    }
}

/// Per-packet ingestion shared by the file builder and live capture.
pub(crate) fn ingest_packet_stats(
    g: &mut RowGroup,
    s: &mut GlobalStats,
    dict: &mut MacDict,
    ip_dict: &mut IpDict,
    rec: &PacketRecord,
    meta: &PacketMeta,
) {
    let blen = rec.origlen as u64;

    // --- row group summary ---
    g.pkt_count += 1;
    g.byte_count += blen;
    g.first_ts = g.first_ts.min(rec.ts_nanos);
    g.last_ts = g.last_ts.max(rec.ts_nanos);
    if meta.ethertype != 0 {
        g.ethertypes.insert(meta.ethertype as u32);
    }
    if let Some(p) = meta.ip_proto {
        g.ipprotos.insert(p);
    }
    if let Some(p) = meta.sport {
        g.port_bloom.insert(&p);
    }
    if let Some(p) = meta.dport {
        g.port_bloom.insert(&p);
    }

    // --- global stats ---
    s.packets += 1;
    s.bytes += blen;
    if rec.ts_nanos != 0 {
        s.first_ts = s.first_ts.min(rec.ts_nanos);
        s.last_ts = s.last_ts.max(rec.ts_nanos);
        s.hist.add(rec.ts_nanos, blen);
    }
    let proto = ProtoKey::of(meta);
    let e = s.protos.entry(proto).or_insert((0, 0));
    e.0 += 1;
    e.1 += blen;
    if let Some(p) = meta.sport {
        s.ports[p as usize] += 1;
    }
    if let Some(p) = meta.dport {
        s.ports[p as usize] += 1;
    }
    if meta.has_eth {
        for mac in [meta.mac_src, meta.mac_dst] {
            let id = dict.intern(mac);
            g.macs.insert(id);
            let m = s.macs.entry(id).or_default();
            if m.pkts == 0 {
                m.first_ts = rec.ts_nanos;
            }
            m.pkts += 1;
            m.bytes += blen;
            m.last_ts = m.last_ts.max(rec.ts_nanos);
            m.protos.insert(proto);
        }
    }

    // --- addresses + conversations ---
    let ids = match meta.net {
        NetAddrs::V4 { src, dst } => {
            g.ip_bloom.insert(&src);
            g.ip_bloom.insert(&dst);
            Some((ip_dict.intern_v4(src), ip_dict.intern_v4(dst)))
        }
        NetAddrs::V6 { src, dst } => {
            g.ip_bloom.insert(&src);
            g.ip_bloom.insert(&dst);
            Some((ip_dict.intern_v6(src), ip_dict.intern_v6(dst)))
        }
        NetAddrs::None => None,
    };
    if let Some((a, b)) = ids {
        let key = (a.min(b), a.max(b));
        let tracked = s.convs.contains_key(&key);
        if tracked || s.convs.len() < CONV_CAP {
            let c = s.convs.entry(key).or_default();
            if c.pkts == 0 {
                c.first_ts = rec.ts_nanos;
            }
            c.pkts += 1;
            c.bytes += blen;
            c.last_ts = c.last_ts.max(rec.ts_nanos);
            c.protos.insert(proto);
            if let Some(p) = meta.sport {
                c.ports.insert(p as u32);
            }
            if let Some(p) = meta.dport {
                c.ports.insert(p as u32);
            }
        } else {
            s.convs_overflow += 1;
        }
    }
}

impl CaptureIndex {
    /// Append one live packet. The open row group is `groups.last()`, so all
    /// existing pruning/walk/aggregate paths see live packets immediately.
    /// Returns the dissected meta so callers can reuse it (filters, display).
    pub fn live_append(&mut self, rec: &PacketRecord, data: &[u8]) -> PacketMeta {
        let need_new = match self.groups.last() {
            Some(g) => g.pkt_count >= ROW_GROUP_SIZE,
            None => true,
        };
        if need_new {
            self.groups
                .push(RowGroup::new(self.stats.packets, rec.record_offset));
        }
        let meta = dissect(rec.linktype, data);
        ingest_packet_stats(
            self.groups.last_mut().unwrap(),
            &mut self.stats,
            &mut self.dict,
            &mut self.ip_dict,
            rec,
            &meta,
        );
        meta
    }
}

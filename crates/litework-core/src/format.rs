//! Capture file access: mmap-backed pcap / pcapng readers that yield
//! `PacketRecord`s carrying exact file offsets, so raw packet bytes can be
//! re-read on demand without ever copying the capture into memory.
//!
//! The walker supports starting from any *record boundary*, which is what lets
//! the tier-0 index prune to a few row groups and rescan only those regions.
//! For pcapng, section state (endianness + interface table) at a boundary is
//! captured in an `NgSnapshot` checkpoint recorded during the initial scan.

use crate::types::*;
use memmap2::Mmap;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a pcap or pcapng file (bad magic)")]
    BadMagic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap { bigendian: bool, nanos: bool },
    PcapNg,
}

/// pcapng section state at some record boundary: current endianness and the
/// interface table (linktype, timestamp ticks/sec) seen so far.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NgSnapshot {
    pub bigendian: bool,
    pub ifaces: Vec<(u16, u64)>,
}

/// Events yielded by the low-level walker.
pub enum Event<'a> {
    /// A packet and its raw bytes (borrowed from the mmap).
    Packet(PacketRecord, &'a [u8]),
    /// pcapng section state changed (SHB or IDB); `u64` is the offset of the
    /// *next* block. Never emitted for legacy pcap.
    NgState(u64, NgSnapshot),
}

/// An opened, mmap'd capture file.
pub struct PcapFile {
    pub path: PathBuf,
    map: Mmap,
    pub format: CaptureFormat,
    /// Linktype of the capture (pcap global header; pcapng first interface
    /// once scanned — per-packet linktype comes from each `PacketRecord`).
    pub linktype: u16,
}

/// Statistics about a completed walk.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanReport {
    pub packets: u64,
    pub bytes_scanned: u64,
    /// File ended mid-record (truncated capture) — everything before that
    /// point is kept rather than failing.
    pub truncated: bool,
}

impl PcapFile {
    pub fn open(path: &Path) -> Result<Self, FormatError> {
        let file = File::open(path)?;
        // Safety: read-only mmap of a capture file. If another process
        // truncates it mid-read we may fault; acceptable for v1.
        let map = unsafe { Mmap::map(&file)? };
        if map.len() < 4 {
            return Err(FormatError::BadMagic);
        }
        let magic = u32::from_le_bytes([map[0], map[1], map[2], map[3]]);
        let (format, linktype) = match magic {
            0xa1b2_c3d4 | 0xa1b2_3c4d | 0xd4c3_b2a1 | 0x4d3c_b2a1 => {
                let (_, hdr) =
                    pcap_parser::parse_pcap_header(&map).map_err(|_| FormatError::BadMagic)?;
                (
                    CaptureFormat::Pcap {
                        bigendian: matches!(magic, 0xd4c3_b2a1 | 0x4d3c_b2a1),
                        nanos: matches!(magic, 0xa1b2_3c4d | 0x4d3c_b2a1),
                    },
                    hdr.network.0 as u16,
                )
            }
            0x0a0d_0d0a => (CaptureFormat::PcapNg, LINKTYPE_ETHERNET),
            _ => return Err(FormatError::BadMagic),
        };
        Ok(PcapFile {
            path: path.to_path_buf(),
            map,
            format,
            linktype,
        })
    }

    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }

    /// Re-map the file if it has grown (live spool support). Existing offsets
    /// stay valid; new packets appended past the old end become readable.
    pub fn refresh(&mut self) -> Result<(), FormatError> {
        let f = std::fs::File::open(&self.path)?;
        let disk_len = f.metadata()?.len();
        if disk_len > self.map.len() as u64 {
            // Safety: same read-only file mapping contract as open().
            self.map = unsafe { Mmap::map(&f)? };
        }
        Ok(())
    }

    /// Hint the kernel that a linear scan is coming (readahead, drop-behind).
    pub fn advise_sequential(&self) {
        #[cfg(unix)]
        let _ = self.map.advise(memmap2::Advice::Sequential);
    }

    /// Hint that access is now random point lookups (queries, hex views).
    pub fn advise_random(&self) {
        #[cfg(unix)]
        let _ = self.map.advise(memmap2::Advice::Random);
    }

    /// Release the page-cache pages backing `[start, start+len)` — used by the
    /// index build to keep resident memory flat while streaming a huge file.
    /// Pages are clean and file-backed; the kernel re-reads on later access.
    pub fn drop_pages(&self, start: u64, len: u64) {
        #[cfg(unix)]
        {
            let page = 4096u64;
            let a = start & !(page - 1);
            let end = (start + len).min(self.map.len() as u64) & !(page - 1);
            if end > a {
                // Safety: read-only file-backed mapping — DONTNEED just drops
                // clean pages; the kernel re-reads from the file on next touch.
                unsafe {
                    let _ = self.map.unchecked_advise_range(
                        memmap2::UncheckedAdvice::DontNeed,
                        a as usize,
                        (end - a) as usize,
                    );
                }
            }
        }
        #[cfg(not(unix))]
        let _ = (start, len);
    }

    pub fn is_empty(&self) -> bool {
        self.map.len() == 0
    }

    /// First `n` bytes of the file (for fingerprinting).
    pub fn head(&self, n: usize) -> &[u8] {
        &self.map[..n.min(self.map.len())]
    }

    /// Raw packet bytes for a record — a borrowed slice of the mmap, zero copy.
    pub fn bytes(&self, rec: &PacketRecord) -> &[u8] {
        let start = (rec.data_offset as usize).min(self.map.len());
        let end = (start + rec.caplen as usize).min(self.map.len());
        &self.map[start..end]
    }

    /// Offset where records begin (start of the whole block stream for pcapng).
    pub fn first_packet_offset(&self) -> u64 {
        match self.format {
            CaptureFormat::Pcap { .. } => 24,
            CaptureFormat::PcapNg => 0,
        }
    }

    /// Walk every packet from the start of the file.
    pub fn for_each_packet<F>(&self, mut f: F) -> Result<ScanReport, FormatError>
    where
        F: FnMut(PacketRecord, &[u8]) -> bool,
    {
        self.for_each_event(self.first_packet_offset(), None, |ev| match ev {
            Event::Packet(rec, data) => f(rec, data),
            Event::NgState(..) => true,
        })
    }

    /// Walk packets starting at a record boundary. For pcapng, `snapshot` must
    /// be the section state checkpoint recorded at or before that boundary.
    pub fn for_each_packet_from<F>(
        &self,
        start: u64,
        snapshot: Option<&NgSnapshot>,
        mut f: F,
    ) -> Result<ScanReport, FormatError>
    where
        F: FnMut(PacketRecord, &[u8]) -> bool,
    {
        self.for_each_event(start, snapshot, |ev| match ev {
            Event::Packet(rec, data) => f(rec, data),
            Event::NgState(..) => true,
        })
    }

    /// Low-level walk: yields packets and (for pcapng) state-change events.
    /// Return `false` from the callback to stop.
    pub fn for_each_event<F>(
        &self,
        start: u64,
        snapshot: Option<&NgSnapshot>,
        mut f: F,
    ) -> Result<ScanReport, FormatError>
    where
        F: for<'a> FnMut(Event<'a>) -> bool,
    {
        match self.format {
            CaptureFormat::Pcap { bigendian, nanos } => {
                self.walk_pcap(start, bigendian, nanos, &mut f)
            }
            CaptureFormat::PcapNg => self.walk_pcapng(start, snapshot, &mut f),
        }
    }

    fn walk_pcap<F>(
        &self,
        start: u64,
        bigendian: bool,
        nanos: bool,
        f: &mut F,
    ) -> Result<ScanReport, FormatError>
    where
        F: for<'a> FnMut(Event<'a>) -> bool,
    {
        let mut report = ScanReport::default();
        let data = &self.map[..];
        let mut cur = start as usize;
        let parse = if bigendian {
            pcap_parser::parse_pcap_frame_be
        } else {
            pcap_parser::parse_pcap_frame
        };
        let sub_factor: u64 = if nanos { 1 } else { 1_000 };
        while cur < data.len() {
            match parse(&data[cur..]) {
                Ok((rem, blk)) => {
                    let consumed = data.len() - cur - rem.len();
                    let rec = PacketRecord {
                        ts_nanos: blk.ts_sec as u64 * 1_000_000_000
                            + blk.ts_usec as u64 * sub_factor,
                        record_offset: cur as u64,
                        data_offset: (cur + 16) as u64,
                        caplen: blk.caplen,
                        origlen: blk.origlen,
                        linktype: self.linktype,
                    };
                    report.packets += 1;
                    let go = f(Event::Packet(rec, blk.data));
                    cur += consumed;
                    if !go {
                        break;
                    }
                }
                Err(_) => {
                    // Incomplete record or trailing garbage: truncated capture.
                    report.truncated = true;
                    break;
                }
            }
        }
        report.bytes_scanned = cur as u64 - start;
        Ok(report)
    }

    fn walk_pcapng<F>(
        &self,
        start: u64,
        snapshot: Option<&NgSnapshot>,
        f: &mut F,
    ) -> Result<ScanReport, FormatError>
    where
        F: for<'a> FnMut(Event<'a>) -> bool,
    {
        use pcap_parser::pcapng::Block;
        let mut report = ScanReport::default();
        let data = &self.map[..];
        let mut cur = start as usize;
        let mut state = snapshot.cloned().unwrap_or_default();
        while cur + 12 <= data.len() {
            // Re-sync endianness at every SHB (raw block type is endian-neutral).
            let raw_type =
                u32::from_le_bytes([data[cur], data[cur + 1], data[cur + 2], data[cur + 3]]);
            if raw_type == 0x0a0d_0d0a {
                let bom = u32::from_le_bytes([
                    data[cur + 8],
                    data[cur + 9],
                    data[cur + 10],
                    data[cur + 11],
                ]);
                if bom != 0x1a2b_3c4d && bom != 0x4d3c_2b1a {
                    report.truncated = true;
                    break;
                }
                state.bigendian = bom == 0x4d3c_2b1a;
                state.ifaces.clear();
            }
            let parse = if state.bigendian {
                pcap_parser::parse_block_be
            } else {
                pcap_parser::parse_block_le
            };
            match parse(&data[cur..]) {
                Ok((rem, block)) => {
                    let consumed = data.len() - cur - rem.len();
                    let next = (cur + consumed) as u64;
                    let go = match block {
                        Block::SectionHeader(_) => f(Event::NgState(next, state.clone())),
                        Block::InterfaceDescription(idb) => {
                            state
                                .ifaces
                                .push((idb.linktype.0 as u16, tsresol_ticks(idb.if_tsresol)));
                            f(Event::NgState(next, state.clone()))
                        }
                        Block::EnhancedPacket(epb) => {
                            let (linktype, tps) = state
                                .ifaces
                                .get(epb.if_id as usize)
                                .copied()
                                .unwrap_or((LINKTYPE_ETHERNET, 1_000_000));
                            let ticks = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                            let rec = PacketRecord {
                                ts_nanos: ticks_to_nanos(ticks, tps),
                                record_offset: cur as u64,
                                data_offset: (cur + 28) as u64,
                                caplen: epb.caplen,
                                origlen: epb.origlen,
                                linktype,
                            };
                            report.packets += 1;
                            let payload = &epb.data[..(epb.caplen as usize).min(epb.data.len())];
                            f(Event::Packet(rec, payload))
                        }
                        Block::SimplePacket(spb) => {
                            let (linktype, _) = state
                                .ifaces
                                .first()
                                .copied()
                                .unwrap_or((LINKTYPE_ETHERNET, 1_000_000));
                            let caplen = spb.data.len().min(spb.origlen as usize) as u32;
                            let rec = PacketRecord {
                                ts_nanos: 0,
                                record_offset: cur as u64,
                                data_offset: (cur + 12) as u64,
                                caplen,
                                origlen: spb.origlen,
                                linktype,
                            };
                            report.packets += 1;
                            f(Event::Packet(rec, &spb.data[..caplen as usize]))
                        }
                        _ => true,
                    };
                    cur += consumed;
                    if !go {
                        break;
                    }
                }
                Err(_) => {
                    report.truncated = true;
                    break;
                }
            }
        }
        report.bytes_scanned = cur as u64 - start;
        Ok(report)
    }
}

/// Decode if_tsresol (pcapng): high bit clear = 10^v ticks/s, set = 2^v.
fn tsresol_ticks(tsresol: u8) -> u64 {
    if tsresol & 0x80 == 0 {
        10u64.checked_pow(tsresol as u32).unwrap_or(1_000_000)
    } else {
        1u64.checked_shl((tsresol & 0x7f) as u32).unwrap_or(1_000_000)
    }
}

fn ticks_to_nanos(ticks: u64, ticks_per_sec: u64) -> u64 {
    if ticks_per_sec == 0 {
        return 0;
    }
    if 1_000_000_000 % ticks_per_sec == 0 {
        ticks.saturating_mul(1_000_000_000 / ticks_per_sec)
    } else {
        ((ticks as u128 * 1_000_000_000u128) / ticks_per_sec as u128) as u64
    }
}

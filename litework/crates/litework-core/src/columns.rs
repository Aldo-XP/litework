//! Per-row-group packet columns (tier-1): fixed-width struct-of-arrays,
//! lz4-compressed per group in the sidecar. Once built, queries and packet
//! lists read these instead of re-dissecting the capture.

use crate::index::{IpDict, MacDict};
use crate::types::*;

pub const F_HAS_ETH: u8 = 1;
pub const F_HAS_PORTS: u8 = 2;
pub const F_HAS_TCPF: u8 = 4;
pub const F_HAS_VLAN: u8 = 8;
pub const F_HAS_IPPROTO: u8 = 16;

pub const NONE_ID: u32 = u32::MAX;

/// Decoded columns for one row group. ~54 B/packet in RAM while cached.
#[derive(Default)]
pub struct GroupColumns {
    pub ts: Vec<u64>,
    pub data_off: Vec<u64>,
    pub caplen: Vec<u32>,
    pub origlen: Vec<u32>,
    pub linktype: Vec<u16>,
    pub vlan: Vec<u16>,
    pub mac_src: Vec<u32>,
    pub mac_dst: Vec<u32>,
    pub ip_src: Vec<u32>,
    pub ip_dst: Vec<u32>,
    pub ipproto: Vec<u16>,
    pub ethertype: Vec<u16>,
    pub sport: Vec<u16>,
    pub dport: Vec<u16>,
    pub tcpflags: Vec<u8>,
    pub flags: Vec<u8>,
}

impl GroupColumns {
    pub fn len(&self) -> usize {
        self.ts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ts.is_empty()
    }

    pub fn approx_bytes(&self) -> usize {
        self.len() * 54 + 64
    }

    pub fn push(&mut self, rec: &PacketRecord, meta: &PacketMeta, dict: &mut MacDict, ips: &mut IpDict) {
        self.ts.push(rec.ts_nanos);
        self.data_off.push(rec.data_offset);
        self.caplen.push(rec.caplen);
        self.origlen.push(rec.origlen);
        self.linktype.push(rec.linktype);
        self.vlan.push(meta.vlan.unwrap_or(0));
        let mut flags = 0u8;
        if meta.has_eth {
            flags |= F_HAS_ETH;
            self.mac_src.push(dict.intern(meta.mac_src));
            self.mac_dst.push(dict.intern(meta.mac_dst));
        } else {
            self.mac_src.push(NONE_ID);
            self.mac_dst.push(NONE_ID);
        }
        match meta.net {
            NetAddrs::V4 { src, dst } => {
                self.ip_src.push(ips.intern_v4(src));
                self.ip_dst.push(ips.intern_v4(dst));
            }
            NetAddrs::V6 { src, dst } => {
                self.ip_src.push(ips.intern_v6(src));
                self.ip_dst.push(ips.intern_v6(dst));
            }
            NetAddrs::None => {
                self.ip_src.push(NONE_ID);
                self.ip_dst.push(NONE_ID);
            }
        }
        if let Some(p) = meta.ip_proto {
            flags |= F_HAS_IPPROTO;
            self.ipproto.push(p as u16);
        } else {
            self.ipproto.push(0);
        }
        self.ethertype.push(meta.ethertype);
        match (meta.sport, meta.dport) {
            (Some(s), Some(d)) => {
                flags |= F_HAS_PORTS;
                self.sport.push(s);
                self.dport.push(d);
            }
            _ => {
                self.sport.push(0);
                self.dport.push(0);
            }
        }
        if let Some(t) = meta.tcp_flags {
            flags |= F_HAS_TCPF;
            self.tcpflags.push(t);
        } else {
            self.tcpflags.push(0);
        }
        if meta.vlan.is_some() {
            flags |= F_HAS_VLAN;
        }
        self.flags.push(flags);
    }

    /// Reconstruct the record + meta for one row, identical to what
    /// `dissect()` produced at index time.
    pub fn row(&self, i: usize, dict: &MacDict, ips: &IpDict) -> (PacketRecord, PacketMeta) {
        let flags = self.flags[i];
        let rec = PacketRecord {
            ts_nanos: self.ts[i],
            // Only used to resume file walks, which the column path never does.
            record_offset: self.data_off[i],
            data_offset: self.data_off[i],
            caplen: self.caplen[i],
            origlen: self.origlen[i],
            linktype: self.linktype[i],
        };
        let mut meta = PacketMeta::empty();
        if flags & F_HAS_ETH != 0 {
            meta.has_eth = true;
            meta.mac_src = dict.get(self.mac_src[i]);
            meta.mac_dst = dict.get(self.mac_dst[i]);
        }
        meta.ethertype = self.ethertype[i];
        if flags & F_HAS_VLAN != 0 {
            meta.vlan = Some(self.vlan[i]);
        }
        meta.net = match (self.ip_src[i], self.ip_dst[i]) {
            (NONE_ID, _) | (_, NONE_ID) => NetAddrs::None,
            (s, d) => ips.net_addrs(s, d),
        };
        if flags & F_HAS_IPPROTO != 0 {
            meta.ip_proto = Some(self.ipproto[i] as u8);
        }
        if flags & F_HAS_PORTS != 0 {
            meta.sport = Some(self.sport[i]);
            meta.dport = Some(self.dport[i]);
        }
        if flags & F_HAS_TCPF != 0 {
            meta.tcp_flags = Some(self.tcpflags[i]);
        }
        (rec, meta)
    }

    /// Serialize to raw bytes (before lz4).
    pub fn encode(&self) -> Vec<u8> {
        let n = self.len();
        let mut out = Vec::with_capacity(4 + n * 54);
        out.extend_from_slice(&(n as u32).to_le_bytes());
        for v in &self.ts {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.data_off {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.caplen {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.origlen {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.linktype {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.vlan {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.mac_src {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.mac_dst {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.ip_src {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.ip_dst {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.ipproto {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.ethertype {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.sport {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.dport {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.tcpflags);
        out.extend_from_slice(&self.flags);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 4 {
            return None;
        }
        let n = u32::from_le_bytes(raw[0..4].try_into().ok()?) as usize;
        if raw.len() != 4 + n * 54 {
            return None;
        }
        let mut pos = 4usize;
        fn take_u64(raw: &[u8], pos: &mut usize, n: usize) -> Vec<u64> {
            let v = raw[*pos..*pos + n * 8]
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect();
            *pos += n * 8;
            v
        }
        fn take_u32(raw: &[u8], pos: &mut usize, n: usize) -> Vec<u32> {
            let v = raw[*pos..*pos + n * 4]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            *pos += n * 4;
            v
        }
        fn take_u16(raw: &[u8], pos: &mut usize, n: usize) -> Vec<u16> {
            let v = raw[*pos..*pos + n * 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
                .collect();
            *pos += n * 2;
            v
        }
        fn take_u8(raw: &[u8], pos: &mut usize, n: usize) -> Vec<u8> {
            let v = raw[*pos..*pos + n].to_vec();
            *pos += n;
            v
        }
        Some(GroupColumns {
            ts: take_u64(raw, &mut pos, n),
            data_off: take_u64(raw, &mut pos, n),
            caplen: take_u32(raw, &mut pos, n),
            origlen: take_u32(raw, &mut pos, n),
            linktype: take_u16(raw, &mut pos, n),
            vlan: take_u16(raw, &mut pos, n),
            mac_src: take_u32(raw, &mut pos, n),
            mac_dst: take_u32(raw, &mut pos, n),
            ip_src: take_u32(raw, &mut pos, n),
            ip_dst: take_u32(raw, &mut pos, n),
            ipproto: take_u16(raw, &mut pos, n),
            ethertype: take_u16(raw, &mut pos, n),
            sport: take_u16(raw, &mut pos, n),
            dport: take_u16(raw, &mut pos, n),
            tcpflags: take_u8(raw, &mut pos, n),
            flags: take_u8(raw, &mut pos, n),
        })
    }
}

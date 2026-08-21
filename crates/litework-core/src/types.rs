//! Core packet types shared across the engine.

/// Location + timing of one packet inside the capture.
/// The raw bytes are NOT stored here — they are read on demand from the
/// mmap'd capture at `data_offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRecord {
    /// Timestamp in nanoseconds since the Unix epoch.
    pub ts_nanos: u64,
    /// Byte offset of the start of this packet's record/block in the file
    /// (a valid position to resume walking from).
    pub record_offset: u64,
    /// Byte offset of the packet data within the capture file.
    pub data_offset: u64,
    /// Captured length (bytes present in the file).
    pub caplen: u32,
    /// Original wire length.
    pub origlen: u32,
    /// Link-layer type (LINKTYPE_*), per interface for pcapng.
    pub linktype: u16,
}

/// Well-known linktypes we dissect. Everything else still gets raw/hex view.
pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_NULL: u16 = 0;
pub const LINKTYPE_LOOP: u16 = 108;
pub const LINKTYPE_LINUX_SLL: u16 = 113;

/// Network-layer addresses extracted from a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetAddrs {
    None,
    V4 { src: [u8; 4], dst: [u8; 4] },
    V6 { src: [u8; 16], dst: [u8; 16] },
}

/// Dissected metadata for one packet. Cheap, fixed-size, no allocation.
#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    pub has_eth: bool,
    pub mac_src: [u8; 6],
    pub mac_dst: [u8; 6],
    /// Final ethertype after any VLAN tags (0 when there is no L2/ethertype).
    pub ethertype: u16,
    /// Innermost VLAN id if tagged.
    pub vlan: Option<u16>,
    pub net: NetAddrs,
    /// IP protocol number (TCP=6, UDP=17, ...) when an IP header was parsed.
    pub ip_proto: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// TCP flags byte (CWR ECE URG ACK PSH RST SYN FIN) when TCP.
    pub tcp_flags: Option<u8>,
}

impl PacketMeta {
    pub fn empty() -> Self {
        PacketMeta {
            has_eth: false,
            mac_src: [0; 6],
            mac_dst: [0; 6],
            ethertype: 0,
            vlan: None,
            net: NetAddrs::None,
            ip_proto: None,
            sport: None,
            dport: None,
            tcp_flags: None,
        }
    }
}

/// A protocol identity used for correlation, stats and queries.
/// `Ip(n)` is an IP protocol number; `Ether(t)` a non-IP ethertype (ARP, LLDP...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtoKey {
    Ip(u8),
    Ether(u16),
    /// No L3 we understand (or unknown linktype).
    Other,
}

impl ProtoKey {
    pub fn of(meta: &PacketMeta) -> ProtoKey {
        if let Some(p) = meta.ip_proto {
            ProtoKey::Ip(p)
        } else if meta.ethertype != 0 {
            ProtoKey::Ether(meta.ethertype)
        } else {
            ProtoKey::Other
        }
    }

    /// Human name from the IANA tables: "tcp", "arp", "goose", falling back
    /// to "ipproto-N" / "ether-0xNNNN" for the truly unknown.
    pub fn name(&self) -> String {
        match self {
            ProtoKey::Ip(p) => match crate::services::ip_proto_name(*p) {
                Some(n) => n.into(),
                None => format!("ipproto-{p}"),
            },
            ProtoKey::Ether(t) => match crate::services::ethertype_name(*t) {
                Some(n) => n.into(),
                None => format!("ether-0x{t:04x}"),
            },
            ProtoKey::Other => "other".into(),
        }
    }
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn fmt_net_addr(net: &NetAddrs) -> (String, String) {
    match net {
        NetAddrs::None => ("-".into(), "-".into()),
        NetAddrs::V4 { src, dst } => (
            std::net::Ipv4Addr::from(*src).to_string(),
            std::net::Ipv4Addr::from(*dst).to_string(),
        ),
        NetAddrs::V6 { src, dst } => (
            std::net::Ipv6Addr::from(*src).to_string(),
            std::net::Ipv6Addr::from(*dst).to_string(),
        ),
    }
}

/// Render epoch nanos as "YYYY-MM-DD HH:MM:SS.mmm" UTC (no chrono dependency).
pub fn fmt_ts(nanos: u64) -> String {
    if nanos == 0 {
        return "-".into();
    }
    let secs = (nanos / 1_000_000_000) as i64;
    let sub_ms = (nanos % 1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{sub_ms:03}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Time-of-day only, "HH:MM:SS.mmm" — for space-tight packet lists (the full
/// date is in the detail pane and overview).
pub fn fmt_ts_short(nanos: u64) -> String {
    if nanos == 0 {
        return "-".into();
    }
    let secs = (nanos / 1_000_000_000) as i64;
    let sub_ms = (nanos % 1_000_000_000) / 1_000_000;
    let tod = secs.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}.{sub_ms:03}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's days-to-civil-date algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

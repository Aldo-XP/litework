//! Cheap per-packet dissection into fixed-size `PacketMeta`.
//! Unknown or unparseable packets never fail — they just yield an empty meta
//! and remain fully viewable as raw bytes.

use crate::types::*;
use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanSlice};
use std::ops::Range;

pub fn dissect(linktype: u16, data: &[u8]) -> PacketMeta {
    let mut meta = PacketMeta::empty();
    match linktype {
        LINKTYPE_ETHERNET => {
            if let Ok(sliced) = LaxSlicedPacket::from_ethernet(data) {
                fill_from_sliced(&mut meta, &sliced);
            }
        }
        LINKTYPE_RAW => {
            if let Ok(sliced) = LaxSlicedPacket::from_ip(data) {
                fill_from_sliced(&mut meta, &sliced);
                // Synthesize the ethertype so proto grouping works uniformly.
                if meta.ethertype == 0 {
                    meta.ethertype = match meta.net {
                        NetAddrs::V4 { .. } => 0x0800,
                        NetAddrs::V6 { .. } => 0x86dd,
                        NetAddrs::None => 0,
                    };
                }
            }
        }
        LINKTYPE_NULL | LINKTYPE_LOOP if data.len() > 4 => {
            // 4-byte AF family header then raw IP.
            {
                if let Ok(sliced) = LaxSlicedPacket::from_ip(&data[4..]) {
                    fill_from_sliced(&mut meta, &sliced);
                    if meta.ethertype == 0 {
                        meta.ethertype = match meta.net {
                            NetAddrs::V4 { .. } => 0x0800,
                            NetAddrs::V6 { .. } => 0x86dd,
                            NetAddrs::None => 0,
                        };
                    }
                }
            }
        }
        _ => {} // unknown linktype: raw view only
    }
    meta
}

fn fill_from_sliced(meta: &mut PacketMeta, s: &LaxSlicedPacket<'_>) {
    if let Some(LinkSlice::Ethernet2(eth)) = &s.link {
        meta.has_eth = true;
        meta.mac_src = eth.source();
        meta.mac_dst = eth.destination();
        meta.ethertype = eth.ether_type().0;
    }
    match &s.vlan {
        Some(VlanSlice::SingleVlan(v)) => {
            meta.vlan = Some(v.vlan_identifier().value());
            meta.ethertype = v.to_header().ether_type.0;
        }
        Some(VlanSlice::DoubleVlan(v)) => {
            let h = v.to_header();
            meta.vlan = Some(h.inner.vlan_id.value());
            meta.ethertype = h.inner.ether_type.0;
        }
        None => {}
    }
    match &s.net {
        Some(LaxNetSlice::Ipv4(ip)) => {
            let h = ip.header();
            meta.net = NetAddrs::V4 {
                src: h.source(),
                dst: h.destination(),
            };
            meta.ip_proto = Some(h.protocol().0);
        }
        Some(LaxNetSlice::Ipv6(ip)) => {
            let h = ip.header();
            meta.net = NetAddrs::V6 {
                src: h.source(),
                dst: h.destination(),
            };
            meta.ip_proto = Some(h.next_header().0);
        }
        None => {}
    }
    match &s.transport {
        Some(TransportSlice::Tcp(t)) => {
            meta.sport = Some(t.source_port());
            meta.dport = Some(t.destination_port());
            let mut flags = 0u8;
            if t.fin() { flags |= 0x01; }
            if t.syn() { flags |= 0x02; }
            if t.rst() { flags |= 0x04; }
            if t.psh() { flags |= 0x08; }
            if t.ack() { flags |= 0x10; }
            if t.urg() { flags |= 0x20; }
            meta.tcp_flags = Some(flags);
            // TCP slices imply IP was parsed; ip_proto already set to 6.
        }
        Some(TransportSlice::Udp(u)) => {
            meta.sport = Some(u.source_port());
            meta.dport = Some(u.destination_port());
        }
        _ => {}
    }
}

/// A labeled byte range within a raw frame — for the TUI's hex↔field
/// highlighting (click a hex byte, see which dissected field it belongs to,
/// and back). Labels match the field names shown in the detail summary
/// (`"eth src"`, `"ip dst"`, `"ports"`, ...) so the two views stay in sync by
/// construction. This is a best-effort, hand-rolled layout walk (not the
/// etherparse lax dissector `dissect()` uses) — it covers the same common
/// cases (Ethernet + optional VLAN tags, IPv4/IPv6, TCP/UDP) plus a trailing
/// `"payload"` span for whatever's left; exotic or malformed framing just
/// yields fewer spans, never a panic (every push is bounds-checked first).
#[derive(Debug, Clone)]
pub struct FieldSpan {
    pub label: &'static str,
    pub range: Range<usize>,
}

fn guess_ip_ethertype(l3: &[u8]) -> u16 {
    match l3.first().map(|b| b >> 4) {
        Some(4) => 0x0800,
        Some(6) => 0x86dd,
        _ => 0,
    }
}

pub fn field_spans(linktype: u16, data: &[u8]) -> Vec<FieldSpan> {
    let mut spans = Vec::new();
    let off;
    let ethertype;
    match linktype {
        LINKTYPE_ETHERNET => {
            if data.len() < 14 {
                return spans;
            }
            spans.push(FieldSpan { label: "eth dst", range: 0..6 });
            spans.push(FieldSpan { label: "eth src", range: 6..12 });
            spans.push(FieldSpan { label: "ethertype", range: 12..14 });
            let mut et = u16::from_be_bytes([data[12], data[13]]);
            let mut cur = 14;
            let mut first = true;
            while matches!(et, 0x8100 | 0x88a8 | 0x9100) && data.len() >= cur + 4 {
                spans.push(FieldSpan {
                    label: if first { "vlan" } else { "vlan (inner)" },
                    range: cur..cur + 4,
                });
                first = false;
                et = u16::from_be_bytes([data[cur + 2], data[cur + 3]]);
                cur += 4;
            }
            off = cur;
            ethertype = et;
        }
        LINKTYPE_RAW => {
            off = 0;
            ethertype = guess_ip_ethertype(data);
        }
        LINKTYPE_NULL | LINKTYPE_LOOP if data.len() > 4 => {
            off = 4;
            ethertype = guess_ip_ethertype(&data[off..]);
        }
        _ => return spans,
    }
    let l3 = match data.get(off..) {
        Some(s) => s,
        None => return spans,
    };
    let mut l4 = None; // (offset, ip protocol)
    if ethertype == 0x0800 && l3.len() >= 20 {
        let ihl = ((l3[0] & 0x0f) as usize * 4).max(20);
        spans.push(FieldSpan { label: "ip proto", range: off + 9..off + 10 });
        spans.push(FieldSpan { label: "ip src", range: off + 12..off + 16 });
        spans.push(FieldSpan { label: "ip dst", range: off + 16..off + 20 });
        l4 = Some((off + ihl, l3[9]));
    } else if ethertype == 0x86dd && l3.len() >= 40 {
        spans.push(FieldSpan { label: "ip proto", range: off + 6..off + 7 });
        spans.push(FieldSpan { label: "ip src", range: off + 8..off + 24 });
        spans.push(FieldSpan { label: "ip dst", range: off + 24..off + 40 });
        l4 = Some((off + 40, l3[6]));
    }
    let mut payload_off = l4.map_or(off, |(o, _)| o);
    if let Some((o, proto)) = l4 {
        if let Some(l4data) = data.get(o..) {
            match proto {
                6 if l4data.len() >= 14 => {
                    spans.push(FieldSpan { label: "ports", range: o..o + 4 });
                    spans.push(FieldSpan { label: "tcp flags", range: o + 13..o + 14 });
                    payload_off = o + ((l4data[12] >> 4) as usize * 4).max(20);
                }
                17 if l4data.len() >= 8 => {
                    spans.push(FieldSpan { label: "ports", range: o..o + 4 });
                    payload_off = o + 8;
                }
                _ => {}
            }
        }
    }
    if payload_off < data.len() {
        spans.push(FieldSpan { label: "payload", range: payload_off..data.len() });
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_tcp() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xbb; 6]); // eth dst
        f.extend_from_slice(&[0xaa; 6]); // eth src
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&[0x45, 0, 0, 42, 0, 0, 0, 0, 64, 6, 0, 0]); // ipv4 hdr, IHL=5
        f.extend_from_slice(&[10, 0, 0, 1]);
        f.extend_from_slice(&[10, 0, 0, 2]);
        f.extend_from_slice(&1234u16.to_be_bytes());
        f.extend_from_slice(&80u16.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        f.push(0x50); // data offset 5
        f.push(0x18); // PSH|ACK
        f.extend_from_slice(&[0x20, 0, 0, 0, 0, 0]);
        f.extend_from_slice(b"hi");
        f
    }

    #[test]
    fn field_spans_eth_ipv4_tcp() {
        let f = eth_ipv4_tcp();
        let spans = field_spans(LINKTYPE_ETHERNET, &f);
        let find = |label: &str| spans.iter().find(|s| s.label == label).map(|s| s.range.clone());
        assert_eq!(find("eth dst"), Some(0..6));
        assert_eq!(find("eth src"), Some(6..12));
        assert_eq!(find("ethertype"), Some(12..14));
        assert_eq!(find("ip proto"), Some(23..24));
        assert_eq!(find("ip src"), Some(26..30));
        assert_eq!(find("ip dst"), Some(30..34));
        assert_eq!(find("ports"), Some(34..38));
        assert_eq!(find("tcp flags"), Some(47..48));
        assert_eq!(find("payload"), Some(54..f.len()));
        for s in &spans {
            assert!(s.range.end <= f.len(), "{}: {:?} out of bounds ({})", s.label, s.range, f.len());
        }
    }

    #[test]
    fn field_spans_unknown_linktype_is_empty() {
        assert!(field_spans(9999, &[1, 2, 3]).is_empty());
    }

    #[test]
    fn field_spans_never_panics_on_short_or_garbage_frames() {
        for len in 0..30 {
            let data = vec![0xffu8; len];
            for lt in [LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_NULL, LINKTYPE_LOOP, 9999] {
                let spans = field_spans(lt, &data);
                for s in &spans {
                    assert!(s.range.end <= data.len());
                }
            }
        }
    }
}

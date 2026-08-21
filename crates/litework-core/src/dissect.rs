//! Cheap per-packet dissection into fixed-size `PacketMeta`.
//! Unknown or unparseable packets never fail — they just yield an empty meta
//! and remain fully viewable as raw bytes.

use crate::types::*;
use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice, VlanSlice};

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

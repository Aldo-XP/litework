//! Synthetic capture generator with exact ground truth, used by integration
//! tests to verify indexing, stats, and query results.
#![allow(dead_code)]

/// Build an Ethernet II frame.
pub fn eth(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Minimal IPv4 header + payload. Checksum left zero (lax parsing).
pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len() as u16;
    let mut p = vec![
        0x45, 0, // ver/ihl, dscp
        (total >> 8) as u8, total as u8,
        0, 0, 0, 0, // id, flags/frag
        64, proto, 0, 0, // ttl, proto, csum
    ];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

/// Minimal TCP header (20 bytes) + payload.
pub fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // seq, ack
    p.push(0x50); // data offset 5
    p.push(flags);
    p.extend_from_slice(&[0x20, 0, 0, 0, 0, 0]); // win, csum, urg
    p.extend_from_slice(payload);
    p
}

/// UDP header + payload.
pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len() as u16;
    let mut p = Vec::with_capacity(len as usize);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// ARP request payload (ethernet/IPv4).
pub fn arp(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
    p.extend_from_slice(&sender_mac);
    p.extend_from_slice(&sender_ip);
    p.extend_from_slice(&[0; 6]);
    p.extend_from_slice(&target_ip);
    p
}

/// Serialize frames into a legacy pcap (LE, usec, LINKTYPE_ETHERNET).
/// `frames` are (ts_micros, bytes).
pub fn to_pcap(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]); // thiszone, sigfigs
    out.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for (ts, frame) in frames {
        out.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

/// Serialize frames into a minimal pcapng (SHB + one IDB + EPBs, LE, usec).
pub fn to_pcapng(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    // SHB
    let shb_len = 28u32;
    out.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
    out.extend_from_slice(&shb_len.to_le_bytes());
    out.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&u64::MAX.to_le_bytes()); // section length unknown
    out.extend_from_slice(&shb_len.to_le_bytes());
    // IDB (no options → default usec resolution)
    let idb_len = 20u32;
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&idb_len.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // LINKTYPE_ETHERNET
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&idb_len.to_le_bytes());
    // EPBs
    for (ts, frame) in frames {
        let pad = (4 - frame.len() % 4) % 4;
        let blen = (32 + frame.len() + pad) as u32;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&blen.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // if_id
        out.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(*ts as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
        out.extend_from_slice(&vec![0u8; pad]);
        out.extend_from_slice(&blen.to_le_bytes());
    }
    out
}

pub const MAC_A: [u8; 6] = [0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x01];
pub const MAC_B: [u8; 6] = [0xbb, 0xbb, 0xbb, 0x00, 0x00, 0x02];
pub const MAC_C: [u8; 6] = [0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x03];

pub const IP_1: [u8; 4] = [10, 0, 0, 1];
pub const IP_2: [u8; 4] = [10, 0, 0, 2];
pub const IP_3: [u8; 4] = [192, 168, 1, 3];

/// The standard test capture:
///   40 × TCP  A→B  10.0.0.1:40000 → 10.0.0.2:443  (SYN)
///   25 × UDP  A→B  10.0.0.1:53000 → 10.0.0.2:53
///   10 × ARP  C→broadcast (sender 192.168.1.3)
///    5 × ICMP B→A  10.0.0.2 → 10.0.0.1
/// Total 80 packets, 1s apart starting at t0.
pub fn standard_frames() -> Vec<(u64, Vec<u8>)> {
    let bcast = [0xff; 6];
    let t0: u64 = 1_700_000_000_000_000; // micros
    let mut frames = Vec::new();
    let mut t = t0;
    for _ in 0..40 {
        frames.push((
            t,
            eth(MAC_A, MAC_B, 0x0800, &ipv4(IP_1, IP_2, 6, &tcp(40_000, 443, 0x02, b"hello"))),
        ));
        t += 1_000_000;
    }
    for _ in 0..25 {
        frames.push((
            t,
            eth(MAC_A, MAC_B, 0x0800, &ipv4(IP_1, IP_2, 17, &udp(53_000, 53, b"dnsq"))),
        ));
        t += 1_000_000;
    }
    for _ in 0..10 {
        frames.push((t, eth(MAC_C, bcast, 0x0806, &arp(MAC_C, IP_3, [192, 168, 1, 1]))));
        t += 1_000_000;
    }
    for _ in 0..5 {
        frames.push((
            t,
            eth(MAC_B, MAC_A, 0x0800, &ipv4(IP_2, IP_1, 1, &[8, 0, 0, 0, 0, 1, 0, 1])),
        ));
        t += 1_000_000;
    }
    frames
}

pub fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("litework-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

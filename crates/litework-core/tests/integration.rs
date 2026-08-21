mod common;

use common::*;
use litework_core::query::run_query;
use litework_core::types::ProtoKey;
use litework_core::{parse_filter, CaptureIndex, OpenOptions, PcapFile};

/// In-memory tier-0 build (no sidecar).
fn build(name: &str, bytes: &[u8]) -> (PcapFile, CaptureIndex) {
    let path = write_temp(name, bytes);
    let file = PcapFile::open(&path).unwrap();
    let index = CaptureIndex::build_in_memory(&file, |_, _| {}).unwrap();
    (file, index)
}

/// Full build persisting a .lwix sidecar next to the temp capture.
fn build_sidecar(name: &str, bytes: &[u8]) -> (PcapFile, CaptureIndex) {
    let path = write_temp(name, bytes);
    let file = PcapFile::open(&path).unwrap();
    let opts = OpenOptions::for_capture(&file);
    let index = CaptureIndex::open(&file, &opts, |_, _| {}).unwrap();
    assert!(index.warning.is_none(), "warning: {:?}", index.warning);
    (file, index)
}

fn count(file: &PcapFile, index: &CaptureIndex, expr: &str) -> u64 {
    let e = parse_filter(expr).unwrap();
    run_query(file, index, &e, |_, _| true).unwrap().matched
}

/// Brute-force count without pruning, to cross-check the pruned path.
fn count_bruteforce(file: &PcapFile, expr: &str) -> u64 {
    let e = parse_filter(expr).unwrap();
    let mut n = 0;
    file.for_each_packet(|rec, data| {
        let meta = litework_core::dissect::dissect(rec.linktype, data);
        if e.matches(&meta, &rec) {
            n += 1;
        }
        true
    })
    .unwrap();
    n
}

#[test]
fn stats_ground_truth_pcap() {
    let (_file, index) = build("std.pcap", &to_pcap(&standard_frames()));
    let s = &index.stats;
    assert_eq!(s.packets, 80);
    assert_eq!(s.protos[&ProtoKey::Ip(6)].0, 40);
    assert_eq!(s.protos[&ProtoKey::Ip(17)].0, 25);
    assert_eq!(s.protos[&ProtoKey::Ether(0x0806)].0, 10);
    assert_eq!(s.protos[&ProtoKey::Ip(1)].0, 5);
    // MAC↔proto correlation: A speaks tcp+udp, B tcp+udp+icmp, C only arp.
    let mac = |m: &[u8; 6]| &s.macs[&index.dict.lookup(m).unwrap()];
    let protos = |m: &[u8; 6]| {
        mac(m).protos.iter().map(|p| p.name()).collect::<Vec<_>>()
    };
    assert_eq!(protos(&MAC_A), ["icmp", "tcp", "udp"]);
    assert_eq!(protos(&MAC_C), ["arp"]);
    assert_eq!(mac(&MAC_A).pkts, 70); // 40 tcp + 25 udp + 5 icmp (as dst)
    assert_eq!(mac(&MAC_C).pkts, 10);
    // Histogram total must equal packet count.
    assert_eq!(s.hist.counts().iter().sum::<u64>(), 80);
    // Time range: 80 packets 1s apart.
    assert_eq!(s.last_ts - s.first_ts, 79 * 1_000_000_000);
    assert!(!index.truncated);
}

#[test]
fn stats_ground_truth_pcapng() {
    let (_file, index) = build("std.pcapng", &to_pcapng(&standard_frames()));
    let s = &index.stats;
    assert_eq!(s.packets, 80);
    assert_eq!(s.protos[&ProtoKey::Ip(6)].0, 40);
    assert_eq!(s.protos[&ProtoKey::Ether(0x0806)].0, 10);
    assert_eq!(s.last_ts - s.first_ts, 79 * 1_000_000_000);
}

#[test]
fn queries_match_ground_truth() {
    let (file, index) = build("q.pcap", &to_pcap(&standard_frames()));
    assert_eq!(count(&file, &index, "proto == tcp"), 40);
    assert_eq!(count(&file, &index, "proto in {tcp, udp}"), 65);
    assert_eq!(count(&file, &index, "proto == arp"), 10);
    assert_eq!(count(&file, &index, "mac == cc:cc:cc:00:00:03"), 10);
    assert_eq!(
        count(&file, &index, "mac == aa:aa:aa:00:00:01 && proto == udp"),
        25
    );
    assert_eq!(count(&file, &index, "mac_src == bb:bb:bb:00:00:02"), 5);
    assert_eq!(count(&file, &index, "ip == 10.0.0.1"), 70);
    assert_eq!(count(&file, &index, "ip_src == 10.0.0.2"), 5);
    assert_eq!(count(&file, &index, "port == 53"), 25);
    assert_eq!(count(&file, &index, "dport == 443"), 40);
    assert_eq!(count(&file, &index, "!(proto == arp)"), 70);
    assert_eq!(count(&file, &index, "proto == tcp || proto == icmp"), 45);
    assert_eq!(count(&file, &index, "len > 10000"), 0);
    assert_eq!(count(&file, &index, "mac == 11:22:33:44:55:66"), 0);
    assert_eq!(count(&file, &index, "ip == 8.8.8.8"), 0);
}

#[test]
fn pruned_equals_bruteforce() {
    // Multi-group capture: >2 row groups of varied traffic, then verify the
    // pruned query path returns exactly the brute-force answer.
    let mut frames = Vec::new();
    let t0: u64 = 1_700_000_000_000_000;
    for i in 0..150_000u64 {
        let ts = t0 + i * 1_000;
        let f = match i % 5 {
            0 => eth(MAC_A, MAC_B, 0x0800, &ipv4(IP_1, IP_2, 6, &tcp(1000 + (i % 100) as u16, 443, 0x10, b""))),
            1 => eth(MAC_B, MAC_A, 0x0800, &ipv4(IP_2, IP_1, 17, &udp(53, 53, b"x"))),
            2 => eth(MAC_C, [0xff; 6], 0x0806, &arp(MAC_C, IP_3, [192, 168, 1, 1])),
            3 => eth(MAC_A, MAC_C, 0x0800, &ipv4(IP_1, IP_3, 1, &[8, 0, 0, 0])),
            _ => eth(MAC_C, MAC_B, 0x0800, &ipv4(IP_3, IP_2, 6, &tcp(2000, 8080, 0x18, b"data"))),
        };
        frames.push((ts, f));
    }
    // Rare needle only in the last group.
    frames.push((
        t0 + 150_000_000,
        eth([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], MAC_A, 0x0800,
            &ipv4([172, 16, 0, 9], IP_1, 6, &tcp(31337, 4444, 0x02, b"needle"))),
    ));
    let (file, index) = build("big.pcap", &to_pcap(&frames));
    assert!(index.groups.len() >= 3, "expected multiple row groups");

    for expr in [
        "proto == tcp",
        "proto == arp && mac == cc:cc:cc:00:00:03",
        "ip == 172.16.0.9",
        "mac == de:ad:be:ef:00:01",
        "port == 4444",
        "dport == 8080 && proto == tcp",
        "(proto == udp || proto == icmp) && ip == 10.0.0.1",
        "len > 60",
    ] {
        let pruned = count(&file, &index, expr);
        let brute = count_bruteforce(&file, expr);
        assert_eq!(pruned, brute, "mismatch for {expr}");
    }

    // The needle query must actually prune: it only exists in the last group.
    let e = parse_filter("mac == de:ad:be:ef:00:01").unwrap();
    let run = run_query(&file, &index, &e, |_, _| true).unwrap();
    assert_eq!(run.matched, 1);
    assert!(
        run.groups_scanned < run.groups_total,
        "expected pruning: scanned {}/{}",
        run.groups_scanned,
        run.groups_total
    );
}

#[test]
fn truncated_capture_is_salvaged() {
    let bytes = to_pcap(&standard_frames());
    let cut = &bytes[..bytes.len() - 30]; // chop mid-record
    let (_file, index) = build("trunc.pcap", cut);
    assert!(index.truncated);
    assert_eq!(index.stats.packets, 79);
}

#[test]
fn raw_bytes_on_demand() {
    let frames = standard_frames();
    let (file, index) = build("raw.pcap", &to_pcap(&frames));
    // Fetch the first TCP packet's bytes via a query and compare to source.
    let e = parse_filter("proto == tcp").unwrap();
    let mut got: Option<Vec<u8>> = None;
    run_query(&file, &index, &e, |rec, _meta| {
        got = Some(file.bytes(rec).to_vec());
        false
    })
    .unwrap();
    assert_eq!(got.unwrap(), frames[0].1);
}

#[test]
fn garbage_file_rejected() {
    let path = write_temp("garbage.bin", b"this is not a capture file at all");
    assert!(PcapFile::open(&path).is_err());
}

#[test]
fn pcap_writer_roundtrip() {
    use litework_core::PcapWriter;
    // Write the standard frames through PcapWriter, reopen, verify identical
    // stats and nanosecond timestamp preservation.
    let frames = standard_frames();
    let path = write_temp("rt-out.pcap", b"");
    let mut w = PcapWriter::create(&path, 1).unwrap();
    for (ts_micros, data) in &frames {
        let nanos = ts_micros * 1_000 + 123; // non-zero sub-microsecond part
        w.write(nanos, data.len() as u32, 1, data).unwrap();
    }
    let (pkts, _, skipped) = w.finish().unwrap();
    assert_eq!(pkts, 80);
    assert_eq!(skipped, 0);

    let file = PcapFile::open(&path).unwrap();
    let index = CaptureIndex::build_in_memory(&file, |_, _| {}).unwrap();
    assert_eq!(index.stats.packets, 80);
    assert_eq!(index.stats.protos[&ProtoKey::Ip(6)].0, 40);
    // nanosecond magic preserves the +123ns exactly
    assert_eq!(index.stats.first_ts % 1_000, 123);
    // raw bytes identical after the roundtrip
    let mut first: Option<Vec<u8>> = None;
    file.for_each_packet(|_rec, data| {
        first = Some(data.to_vec());
        false
    })
    .unwrap();
    assert_eq!(first.unwrap(), frames[0].1);

    // Mixed-linktype packets are skipped, not corrupted.
    let path2 = write_temp("rt-mixed.pcap", b"");
    let mut w = PcapWriter::create(&path2, 1).unwrap();
    w.write(1, 10, 1, &frames[0].1).unwrap();
    w.write(2, 10, 101, &[0u8; 10]).unwrap(); // RAW linktype — skipped
    let (pkts, _, skipped) = w.finish().unwrap();
    assert_eq!((pkts, skipped), (1, 1));
}

#[test]
fn wildcards_ranges_ground_truth() {
    let (file, index) = build("wild.pcap", &to_pcap(&standard_frames()));
    // Wildcard IP octets: 10.0.0.* matches both LAN hosts (70 pkts involve them).
    assert_eq!(count(&file, &index, "ip == 10.0.0.*"), 70);
    assert_eq!(count(&file, &index, "ip == 10.*"), 70);
    // .2 appears as dst in tcp+udp (65) and as src in icmp (5)
    assert_eq!(count(&file, &index, "ip == 10.0.*.2"), 70);
    assert_eq!(count(&file, &index, "ip_dst == 10.0.*.2"), 65);
    assert_eq!(count(&file, &index, "ip == 192.168.*"), 0); // ARP has no IP header
    // CIDR
    assert_eq!(count(&file, &index, "ip == 10.0.0.0/24"), 70);
    assert_eq!(count(&file, &index, "ip == 10.0.0.0/30"), 70);
    assert_eq!(count(&file, &index, "ip_src == 10.0.0.0/31"), 65); // .1 only src of tcp+udp
    assert_eq!(count(&file, &index, "ip == 172.16.0.0/12"), 0);
    // MAC wildcards
    assert_eq!(count(&file, &index, "mac == aa:aa:aa:*"), 70);
    assert_eq!(count(&file, &index, "mac == cc:cc:cc:*:*:03"), 10);
    assert_eq!(count(&file, &index, "mac_src == *:*:*:*:*:02"), 5);
    assert_eq!(count(&file, &index, "mac == ff:*"), 10); // broadcast dst of ARP
    // Port ranges
    assert_eq!(count(&file, &index, "port == 40000-50000"), 40);
    assert_eq!(count(&file, &index, "port == 50-60"), 25);
    assert_eq!(count(&file, &index, "sport == 39000-41000"), 40);
    assert_eq!(count(&file, &index, "port in {443, 50-60}"), 65);
    assert_eq!(count(&file, &index, "len == 60-64"), count_bruteforce(&file, "len == 60-64"));
}

#[test]
fn sidecar_roundtrip_and_columns() {
    let mut frames = Vec::new();
    let t0: u64 = 1_700_000_000_000_000;
    for i in 0..150_000u64 {
        let ts = t0 + i * 1_000;
        let f = match i % 5 {
            0 => eth(MAC_A, MAC_B, 0x0800, &ipv4(IP_1, IP_2, 6, &tcp(1000 + (i % 100) as u16, 443, 0x10, b""))),
            1 => eth(MAC_B, MAC_A, 0x0800, &ipv4(IP_2, IP_1, 17, &udp(53, 53, b"x"))),
            2 => eth(MAC_C, [0xff; 6], 0x0806, &arp(MAC_C, IP_3, [192, 168, 1, 1])),
            3 => eth(MAC_A, MAC_C, 0x0800, &ipv4(IP_1, IP_3, 1, &[8, 0, 0, 0])),
            _ => eth(MAC_C, MAC_B, 0x0800, &ipv4(IP_3, IP_2, 6, &tcp(2000, 8080, 0x18, b"data"))),
        };
        frames.push((ts, f));
    }
    let bytes = to_pcap(&frames);

    // Build fresh (writes sidecar), then reopen (loads sidecar).
    let (file, fresh) = build_sidecar("sc.pcap", &bytes);
    assert!(fresh.sidecar.is_some(), "fresh build should carry columns");
    let opts = OpenOptions::for_capture(&file);
    let loaded = CaptureIndex::open(&file, &opts, |_, _| {}).unwrap();
    assert!(loaded.loaded_from_sidecar);
    assert!(loaded.sidecar.is_some());

    // Same stats after load.
    assert_eq!(loaded.stats.packets, fresh.stats.packets);
    assert_eq!(loaded.stats.bytes, fresh.stats.bytes);
    assert_eq!(loaded.stats.protos.len(), fresh.stats.protos.len());
    assert_eq!(loaded.stats.convs.len(), fresh.stats.convs.len());
    assert_eq!(loaded.dict.len(), fresh.dict.len());
    assert_eq!(loaded.groups.len(), fresh.groups.len());
    assert_eq!(
        loaded.stats.hist.counts().iter().sum::<u64>(),
        fresh.stats.hist.counts().iter().sum::<u64>()
    );

    // Column path == walk path for a battery of queries (incl. wildcards).
    let (_f2, plain) = build("sc-plain.pcap", &bytes);
    for expr in [
        "proto == tcp",
        "ip == 10.0.*",
        "ip == 192.168.1.0/24",
        "mac == cc:cc:cc:*",
        "port == 8000-8100",
        "dport == 8080 && proto == tcp",
        "(proto == udp || proto == icmp) && ip == 10.0.0.1",
        "vlan == 1-100",
        "len == 54-60",
    ] {
        let via_cols = count(&file, &loaded, expr);
        let via_walk = count(&file, &plain, expr);
        assert_eq!(via_cols, via_walk, "column/walk mismatch for {expr}");
    }

    // Conversations tracked: 3 distinct IP pairs (1↔2, 1↔3, 3↔2).
    assert_eq!(loaded.stats.convs.len(), 3);
    let total_conv_pkts: u64 = loaded.stats.convs.values().map(|c| c.pkts).sum();
    assert_eq!(total_conv_pkts, 120_000); // all but the 30k ARP frames

    // Modified capture invalidates the sidecar.
    let mut extended = bytes.clone();
    extended.extend_from_slice(&to_pcap(&standard_frames())[24..]);
    let path = write_temp("sc.pcap", &extended); // overwrite same file
    let file2 = PcapFile::open(&path).unwrap();
    let opts2 = OpenOptions::for_capture(&file2);
    let rebuilt = CaptureIndex::open(&file2, &opts2, |_, _| {}).unwrap();
    assert!(!rebuilt.loaded_from_sidecar, "stale sidecar must not load");
    assert_eq!(rebuilt.stats.packets, 150_080);
}

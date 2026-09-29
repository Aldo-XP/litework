//! Round-trip tests for the `.lwz` archive: every input must come back
//! byte-for-byte, including malformed and adversarial ones.

use litework_pack::{self as pack, PackOptions, Reader};
use std::io::Cursor;

/// Tiny deterministic PRNG so tests need no extra deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

fn cksum(b: &[u8]) -> u16 {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn ipv4(r: &mut Rng, src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8], id: u16) -> Vec<u8> {
    let opts = if r.chance(5) { vec![0x94, 0x04, 0, 0] } else { vec![] };
    let ihl = 5 + opts.len() / 4;
    let tot = (ihl * 4 + payload.len()) as u16;
    let mut h = vec![0x40 | ihl as u8, r.below(4) as u8 * 0xb8 / 3, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    h[2..4].copy_from_slice(&tot.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(&opts);
    let ck = cksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    if r.chance(10) {
        h[0] = 0xb0 | (h[0] & 0x0f); // mangled version nibble
    }
    if r.chance(5) {
        h[10] ^= 0x05; // broken checksum
    }
    h.extend_from_slice(payload);
    h
}

fn l4(r: &mut Rng, proto: u8, src: [u8; 4], dst: [u8; 4], seq: &mut u32, data: &[u8]) -> Vec<u8> {
    let sp = 1024 + r.below(60000) as u16;
    let dp = [53u16, 80, 443, 12000][r.below(4) as usize];
    let mut seg = Vec::new();
    seg.extend_from_slice(&sp.to_be_bytes());
    seg.extend_from_slice(&dp.to_be_bytes());
    match proto {
        6 => {
            let opts: Vec<u8> = if r.chance(50) { vec![1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8] } else { vec![] };
            let doff = (20 + opts.len()) / 4;
            seg.extend_from_slice(&seq.to_be_bytes());
            seg.extend_from_slice(&(r.next() as u32).to_be_bytes());
            let flags = if r.chance(3) { 0x02 } else { 0x18 };
            seg.push((doff as u8) << 4);
            seg.push(flags);
            seg.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
            seg.extend_from_slice(&opts);
            seg.extend_from_slice(data);
            *seq = seq.wrapping_add(data.len() as u32 + (flags & 2 != 0) as u32);
        }
        17 => {
            let mut l = (8 + data.len()) as u16;
            if r.chance(3) {
                l = l.wrapping_add(7); // bogus UDP length
            }
            seg.extend_from_slice(&l.to_be_bytes());
            seg.extend_from_slice(&[0, 0]);
            seg.extend_from_slice(data);
        }
        _ => unreachable!(),
    }
    let ck_off = if proto == 6 { 16 } else { 6 };
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&seg);
    let mut ck = cksum(&pseudo);
    if r.chance(10) {
        ck = 0;
    }
    seg[ck_off..ck_off + 2].copy_from_slice(&ck.to_be_bytes());
    seg
}

fn random_frame(r: &mut Rng, seqs: &mut [u32; 8], ids: &mut [u16; 8]) -> Vec<u8> {
    let fl = r.below(8) as usize;
    let src = [10, 0, 0, fl as u8];
    let dst = [10, 0, 1, (fl * 3) as u8];
    let mut eth = vec![0, 0, 0, 0, 0, fl as u8, 0, 0, 0, 0, 1, fl as u8];
    if r.chance(15) {
        eth.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
    }
    let data = match r.below(4) {
        0 => vec![],
        1 => {
            let n = r.below(1400) as usize;
            r.bytes(n)
        }
        2 => b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".repeat(r.below(5) as usize + 1),
        _ => vec![0u8; r.below(200) as usize],
    };
    ids[fl] = ids[fl].wrapping_add(1);
    let mut ethertype = [0x08u8, 0x00];
    let pkt = match r.below(10) {
        0..=3 => {
            let seg = l4(r, 6, src, dst, &mut seqs[fl], &data);
            ipv4(r, src, dst, 6, &seg, ids[fl])
        }
        4..=6 => {
            let seg = l4(r, 17, src, dst, &mut seqs[fl], &data);
            ipv4(r, src, dst, 17, &seg, ids[fl])
        }
        7 => ipv4(r, src, dst, 115, &data, ids[fl]),
        8 => {
            ethertype = [0x08, 0x06];
            r.bytes(28)
        }
        _ => {
            let mut b = vec![0x90];
            b.extend(r.bytes(40));
            b
        }
    };
    eth.extend_from_slice(&ethertype);
    let mut f = eth;
    f.extend_from_slice(&pkt);
    match r.below(50) {
        0 => {
            let n = r.below(f.len() as u64 + 1) as usize;
            f.truncate(n) // snaplen cut
        }
        1 => {
            let n = r.below(20) as usize;
            f = r.bytes(n) // garbage
        }
        _ => {}
    }
    f
}

fn build_pcap(r: &mut Rng, n: usize, magic: u32, linktype: u32, tail: &[u8]) -> Vec<u8> {
    let be = matches!(magic, 0xd4c3_b2a1 | 0x4d3c_b2a1);
    let nanos = matches!(magic, 0xa1b2_3c4d | 0x4d3c_b2a1);
    let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let mut out = Vec::new();
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&w32(linktype));
    let mut ts: u64 = 1_700_000_000_000_000_000;
    let mut seqs = [0u32; 8];
    let mut ids = [0u16; 8];
    for _ in 0..n {
        ts += r.below(50_000);
        let f = random_frame(r, &mut seqs, &mut ids);
        let sub = if nanos { ts % 1_000_000_000 } else { (ts % 1_000_000_000) / 1000 };
        let mut sub = sub as u32;
        if r.chance(1) {
            sub = 3_000_000_000; // malformed timestamp
        }
        out.extend_from_slice(&w32((ts / 1_000_000_000) as u32));
        out.extend_from_slice(&w32(sub));
        out.extend_from_slice(&w32(f.len() as u32));
        out.extend_from_slice(&w32(f.len() as u32 + r.below(3) as u32 * 100));
        out.extend_from_slice(&f);
    }
    out.extend_from_slice(tail);
    out
}

fn roundtrip_pcap(data: &[u8], block_bytes: usize) -> Vec<u8> {
    let opts = PackOptions { level: 3, block_bytes, threads: 4 };
    let w = pack::pcap::pack(Cursor::new(data.to_vec()), Vec::new(), &opts, None).unwrap();
    let (arc, summary) = w.finish().unwrap();
    assert!(summary.blocks >= 1 || data.len() <= 24);
    let mut out = Vec::new();
    pack::pcap::unpack(Reader::new(Cursor::new(arc)).unwrap(), &mut out).unwrap();
    out
}

#[test]
fn pcap_roundtrip_all_variants() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for &magic in &[0xa1b2_c3d4u32, 0xa1b2_3c4d, 0xd4c3_b2a1, 0x4d3c_b2a1] {
        for &linktype in &[1u32, 101, 147] {
            let data = build_pcap(&mut r, 3000, magic, linktype, b"\x01\x02\x03");
            let out = roundtrip_pcap(&data, 40_000); // many small blocks
            assert!(out == data, "mismatch magic={magic:#x} linktype={linktype}");
        }
    }
}

#[test]
fn pcap_roundtrip_big_block_and_compresses_headers() {
    let mut r = Rng(42);
    let data = build_pcap(&mut r, 20_000, 0xa1b2_c3d4, 1, b"");
    let opts = PackOptions { level: 5, block_bytes: 1 << 30, threads: 4 };
    let w = pack::pcap::pack(Cursor::new(data.clone()), Vec::new(), &opts, None).unwrap();
    let (arc, summary) = w.finish().unwrap();
    assert_eq!(summary.blocks, 1);
    // Header columns must be a small fraction of the packed size.
    let hdr: u64 = summary
        .stats
        .iter()
        .filter(|(k, _)| **k & pack::packet::K_CLASS_BASE == 0)
        .map(|(_, s)| s.comp)
        .sum();
    assert!(hdr * 4 < arc.len() as u64, "headers {hdr} of {}", arc.len());
    let mut out = Vec::new();
    pack::pcap::unpack(Reader::new(Cursor::new(arc)).unwrap(), &mut out).unwrap();
    assert!(out == data);
}

#[test]
fn pcap_truncated_mid_packet() {
    let mut r = Rng(7);
    let mut data = build_pcap(&mut r, 50, 0xa1b2_c3d4, 1, b"");
    data.truncate(data.len() - 5);
    assert!(roundtrip_pcap(&data, 1 << 20) == data);
    // Header only + partial record header.
    let data2 = data[..24 + 9].to_vec();
    assert!(roundtrip_pcap(&data2, 1 << 20) == data2);
}

// ---------------------------------------------------------------------------

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn bbframe(r: &mut Rng, ids: &mut [u16; 8], seqs: &mut [u32; 8]) -> Vec<u8> {
    let dfl_bytes = [825usize, 1510, 3072][r.below(3) as usize];
    let mut data = Vec::new();
    while data.len() + 80 < dfl_bytes {
        let fl = r.below(8) as usize;
        let src = [10, 0, 0, fl as u8];
        let dst = [10, 0, 1, fl as u8];
        ids[fl] = ids[fl].wrapping_add(1);
        let body: Vec<u8> = match r.below(5) {
            0..=2 => {
                let n = r.below(200) as usize;
                let payload = r.bytes(n);
                let seg = l4(r, 17, src, dst, &mut seqs[fl], &payload);
                let mut pre = vec![0, 2, 0, 0x82, fl as u8, 0xc0, 1, 0, 0];
                if r.chance(20) {
                    pre[7..9].copy_from_slice(&[4, 0xc0]);
                }
                pre.extend(ipv4(r, src, dst, 17, &seg, ids[fl]));
                pre
            }
            3 => {
                let mut b = vec![0, 2, 0, 0x82, fl as u8, 0xc0, 1, 0, 0x90];
                b.extend(r.bytes(32));
                b
            }
            _ => {
                let n = r.below(60) as usize + 1;
                r.bytes(n) // arbitrary junk packet
            }
        };
        let len = 2 + body.len();
        if data.len() + len > dfl_bytes {
            break;
        }
        data.extend_from_slice(&(0xc000 | len as u16).to_be_bytes());
        data.extend_from_slice(&body);
    }
    // Padding (zeros) + sometimes a non-zero tail.
    data.resize(dfl_bytes, 0);
    if r.chance(30) {
        let n = data.len();
        data[n - 4..].copy_from_slice(&r.bytes(4));
    }
    let mut f = vec![0x16, 0, 0, 0];
    f.extend_from_slice(&((dfl_bytes * 8) as u16).to_be_bytes());
    f.extend_from_slice(&[0xe3, 0, 0, r.next() as u8]);
    f.extend_from_slice(&data);
    if r.chance(5) {
        f.extend(r.bytes(3)); // bytes after the data field
    }
    if r.chance(2) {
        f[4] = 0xff; // DFL overruns the frame → raw fallback
    }
    f
}

fn build_jsonl(r: &mut Rng, n: usize, final_newline: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ts: u64 = 1_787_035_353_906_961;
    let mut ids = [0u16; 8];
    let mut seqs = [0u32; 8];
    for i in 0..n {
        ts += r.below(5_000);
        let frac_digits = if r.chance(70) { 6 } else { 7 };
        let tstr = if frac_digits == 6 {
            format!("{}.{:06}", ts / 1_000_000, ts % 1_000_000)
        } else {
            format!("{}.{:07}", ts / 1_000_000, (ts % 1_000_000) * 10 + r.below(10))
        };
        let frame = bbframe(r, &mut ids, &mut seqs);
        let meta = format!(r#"{{"ma_hdr":"{}","udp_dst":{}}}"#, ["bQ==", "cg=="][r.below(2) as usize], 12 + r.below(2));
        let mut line = format!(r#"{{"timestamp":{tstr},"bbframe":"{}","metadata":{meta}}}"#, b64(&frame));
        match r.below(40) {
            0 => line = format!(r#"{{"other":{i}}}"#),
            1 => line = line.replacen("\"bbframe\":\"", "\"bbframe\":\"!!", 1),
            2 => line = line.replacen(&tstr, "1.5e9", 1),
            3 => line = line.replacen(&tstr, &format!("0{tstr}"), 1),
            4 => line.push('\r'),
            5 => line = String::new(),
            6 => line = line.replacen("\"metadata\":", "\"metadata\": ", 1),
            _ => {}
        }
        out.extend_from_slice(line.as_bytes());
        if i + 1 < n || final_newline {
            out.push(b'\n');
        }
    }
    out
}

fn roundtrip_jsonl(data: &[u8], block_bytes: usize) -> Vec<u8> {
    let opts = PackOptions { level: 3, block_bytes, threads: 4 };
    let (w, _) = pack::jsonl::pack(Cursor::new(data.to_vec()), Vec::new(), &opts, false, None).unwrap();
    let (arc, _) = w.finish().unwrap();
    let mut out = Vec::new();
    pack::jsonl::unpack(Reader::new(Cursor::new(arc)).unwrap(), &mut out).unwrap();
    out
}

#[test]
fn jsonl_roundtrip() {
    let mut r = Rng(123);
    for &nl in &[true, false] {
        let data = build_jsonl(&mut r, 1500, nl);
        assert!(roundtrip_jsonl(&data, 100_000) == data, "final_newline={nl}");
        assert!(roundtrip_jsonl(&data, 1 << 30) == data);
    }
    assert!(roundtrip_jsonl(b"", 1 << 20).is_empty());
    // Strict mode refuses the first malformed line.
    let opts = PackOptions { level: 1, block_bytes: 1 << 20, threads: 1 };
    let r = pack::jsonl::pack(Cursor::new(b"{\"x\":1}\n".to_vec()), Vec::new(), &opts, true, None);
    assert!(matches!(r, Err(pack::PackError::Unsupported(_))));
    assert_eq!(roundtrip_jsonl(b"\n\n", 1 << 20), b"\n\n");
    assert_eq!(roundtrip_jsonl(b"not json", 1 << 20), b"not json");
}

#[test]
fn jsonl_example_line_models_as_structured() {
    // The real-world sample: must round-trip and must NOT fall back to raw.
    let line = include_str!("data/bbframe_example.jsonl");
    let data = line.as_bytes().to_vec();
    let opts = PackOptions { level: 3, block_bytes: 1 << 20, threads: 2 };
    let (w, report) = pack::jsonl::pack(Cursor::new(data.clone()), Vec::new(), &opts, true, None).unwrap();
    assert_eq!(report.modelled, 1);
    assert_eq!(report.gse_ipv4 + report.gse_opaque, report.gse_packets);
    assert!(report.gse_ipv4 >= 3);
    let (arc, summary) = w.finish().unwrap();
    assert!(!summary.stats.contains_key(&pack::jsonl::K_LRAW), "line stored raw");
    assert!(!summary.stats.contains_key(&pack::jsonl::K_BBRAW), "frame stored raw");
    let gse = summary.stats[&pack::jsonl::K_GSECNT].raw;
    assert_eq!(gse, 1);
    // Several IPv4 packets were recognised inside the frame.
    assert!(summary.stats.contains_key(&pack::packet::K_IPCK));
    let mut out = Vec::new();
    pack::jsonl::unpack(Reader::new(Cursor::new(arc)).unwrap(), &mut out).unwrap();
    assert!(out == data);
}

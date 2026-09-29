//! Legacy pcap ⇄ `.lwz`. The 24-byte file header is stored verbatim; each
//! record header becomes a timestamp delta + caplen + (origlen − caplen), and
//! the packet bytes go through the packet model.
//!
//! pcapng is not supported yet (convert with `litework export` or editcap).

use super::packet::{Layer, PacketDecoder, PacketEncoder};
use super::{Cols, PackError, PackOptions, Reader, Result, Writer, KIND_PCAP};
use std::io::{Read, Write};

pub const K_PREFIX: u32 = 100;
pub const K_TAIL: u32 = 101;
pub const K_RECKIND: u32 = 102;
pub const K_RECRAW: u32 = 103;
pub const K_TS: u32 = 104;
pub const K_CAPLEN: u32 = 105;
pub const K_ORIGD: u32 = 106;

pub fn col_name(key: u32) -> Option<String> {
    Some(
        match key {
            K_PREFIX => "pcap.header",
            K_TAIL => "pcap.tail",
            K_RECKIND => "rec.kind",
            K_RECRAW => "rec.raw",
            K_TS => "rec.ts.delta",
            K_CAPLEN => "rec.caplen",
            K_ORIGD => "rec.origlen.res",
            _ => return None,
        }
        .to_string(),
    )
}

struct Header {
    bigendian: bool,
    nanos: bool,
    layer: Layer,
}

fn parse_header(h: &[u8; 24]) -> Result<Header> {
    let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let (bigendian, nanos) = match magic {
        0xa1b2_c3d4 => (false, false),
        0xa1b2_3c4d => (false, true),
        0xd4c3_b2a1 => (true, false),
        0x4d3c_b2a1 => (true, true),
        0x0a0d_0d0a => {
            return Err(PackError::Unsupported(
                "pcapng input — convert to pcap first (litework export, or editcap -F pcap)".into(),
            ))
        }
        _ => return Err(PackError::Unsupported("not a pcap file (bad magic)".into())),
    };
    let rd32 = |b: &[u8]| {
        let a = [b[0], b[1], b[2], b[3]];
        if bigendian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    let linktype = rd32(&h[20..24]) & 0x0fff_ffff;
    let layer = match linktype {
        1 => Layer::Ethernet,
        12 | 101 | 228 => Layer::RawIp,
        _ => Layer::Opaque,
    };
    Ok(Header { bigendian, nanos, layer })
}

/// Progress callback: (bytes consumed, packets so far).
pub type Progress<'a> = dyn FnMut(u64, u64) + 'a;

pub fn pack<R: Read, W: Write + Send + 'static>(
    mut inp: R,
    out: W,
    opts: &PackOptions,
    mut progress: Option<&mut Progress<'_>>,
) -> Result<Writer<W>> {
    let mut hdr = [0u8; 24];
    inp.read_exact(&mut hdr)?;
    let h = parse_header(&hdr)?;
    let sub_limit: u64 = if h.nanos { 1_000_000_000 } else { 1_000_000 };
    let sub_mul: u64 = if h.nanos { 1 } else { 1_000 };
    let rd32 = |b: &[u8]| {
        let a = [b[0], b[1], b[2], b[3]];
        if h.bigendian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };

    let mut w = Writer::new(out, KIND_PCAP, opts.clone())?;
    let mut cols = Cols::default();
    cols.bytes(K_PREFIX, &hdr);
    let mut enc = PacketEncoder::new();
    enc.begin_block();
    let mut block_items = 0u64;
    let mut block_raw = 0usize;
    let mut prev_ts: i64 = 0;
    let mut consumed = 24u64;
    let mut packets = 0u64;
    let mut rec = [0u8; 16];
    let mut buf: Vec<u8> = Vec::with_capacity(65_536);

    loop {
        // Record header (may be truncated at EOF).
        let got = read_upto(&mut inp, &mut rec)?;
        if got < 16 {
            if got > 0 {
                cols.bytes(K_TAIL, &rec[..got]);
            }
            break;
        }
        let ts_sec = rd32(&rec[0..4]) as u64;
        let ts_sub = rd32(&rec[4..8]) as u64;
        let caplen = rd32(&rec[8..12]) as usize;
        let origlen = rd32(&rec[12..16]);
        buf.clear();
        buf.resize(caplen, 0);
        let got = read_upto(&mut inp, &mut buf)?;
        if got < caplen {
            cols.bytes(K_TAIL, &rec);
            cols.bytes(K_TAIL, &buf[..got]);
            break;
        }
        consumed += 16 + caplen as u64;
        packets += 1;

        if ts_sub >= sub_limit {
            // Malformed timestamp: keep the record header verbatim.
            cols.u8(K_RECKIND, 1);
            cols.bytes(K_RECRAW, &rec);
        } else {
            cols.u8(K_RECKIND, 0);
            let ts = (ts_sec * 1_000_000_000 + ts_sub * sub_mul) as i64;
            cols.zig(K_TS, ts.wrapping_sub(prev_ts));
            prev_ts = ts;
            cols.varint(K_CAPLEN, caplen as u64);
            cols.zig(K_ORIGD, origlen as i64 - caplen as i64);
        }
        enc.encode(&mut cols, &buf, h.layer, None);
        block_items += 1;
        block_raw += 16 + caplen;

        if block_raw >= opts.block_bytes {
            enc.finish_block(&mut cols);
            w.write_block(block_items, &mut cols)?;
            enc.begin_block();
            block_items = 0;
            block_raw = 0;
            prev_ts = 0;
            if let Some(p) = progress.as_mut() {
                p(consumed, packets);
            }
        }
    }
    enc.finish_block(&mut cols);
    if block_items > 0 || !cols.is_empty() {
        w.write_block(block_items.max(1), &mut cols)?;
    }
    if let Some(p) = progress.as_mut() {
        p(consumed, packets);
    }
    Ok(w)
}

fn read_upto<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub fn unpack<R: Read, W: Write>(mut rd: Reader<R>, mut out: W) -> Result<u64> {
    let mut dec = PacketDecoder::new();
    let mut header: Option<Header> = None;
    let mut bigendian = false;
    let mut nanos = false;
    let mut packets = 0u64;
    let mut first = true;
    while let Some((items, mut cols)) = rd.next_block()? {
        if first {
            first = false;
            let pre = cols.rest(K_PREFIX);
            if pre.len() != 24 {
                return super::fmt_err("missing pcap header column");
            }
            let h = parse_header(&pre.clone().try_into().unwrap())?;
            bigendian = h.bigendian;
            nanos = h.nanos;
            header = Some(h);
            out.write_all(&pre)?;
        }
        let layer = header.as_ref().unwrap().layer;
        let sub_div: u64 = if nanos { 1 } else { 1_000 };
        dec.begin_block();
        // Phase 1: record headers + packet headers.
        struct Rec {
            hdr: [u8; 16],
            pkt: usize,
        }
        let mut recs: Vec<Rec> = Vec::with_capacity(items as usize);
        let mut prev_ts: i64 = 0;
        let nrec = if cols.has(K_RECKIND) { items } else { 0 };
        for _ in 0..nrec {
            let kind = cols.u8(K_RECKIND)?;
            let mut hdr = [0u8; 16];
            let caplen;
            if kind == 1 {
                hdr.copy_from_slice(cols.take(K_RECRAW, 16)?);
                let a = [hdr[8], hdr[9], hdr[10], hdr[11]];
                caplen = if bigendian {
                    u32::from_be_bytes(a)
                } else {
                    u32::from_le_bytes(a)
                } as usize;
            } else {
                let ts = prev_ts.wrapping_add(cols.zig(K_TS)?);
                prev_ts = ts;
                caplen = cols.varint(K_CAPLEN)? as usize;
                let origlen = (cols.zig(K_ORIGD)? + caplen as i64) as u32;
                let sec = (ts as u64 / 1_000_000_000) as u32;
                let sub = ((ts as u64 % 1_000_000_000) / sub_div) as u32;
                let put = |v: u32| if bigendian { v.to_be_bytes() } else { v.to_le_bytes() };
                hdr[0..4].copy_from_slice(&put(sec));
                hdr[4..8].copy_from_slice(&put(sub));
                hdr[8..12].copy_from_slice(&put(caplen as u32));
                hdr[12..16].copy_from_slice(&put(origlen));
            }
            let pkt = dec.decode(&mut cols, caplen, layer)?;
            recs.push(Rec { hdr, pkt });
        }
        dec.resolve(&mut cols)?;
        // Phase 2: emit.
        let mut pb: Vec<u8> = Vec::with_capacity(65_536);
        for r in &recs {
            out.write_all(&r.hdr)?;
            pb.clear();
            dec.bytes(r.pkt, &mut pb);
            out.write_all(&pb)?;
            packets += 1;
        }
        let tail = cols.rest(K_TAIL);
        out.write_all(&tail)?;
    }
    out.flush()?;
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_pcapng() {
        let mut h = [0u8; 24];
        h[..4].copy_from_slice(&0x0a0d_0d0au32.to_le_bytes());
        let mut raw = h.to_vec();
        raw.extend_from_slice(&[0u8; 40]);
        let r = pack(Cursor::new(raw), Vec::new(), &PackOptions::default(), None);
        assert!(matches!(r, Err(PackError::Unsupported(_))));
    }

    #[test]
    fn empty_pcap_roundtrips() {
        let mut h = [0u8; 24];
        h[..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        h[20] = 1;
        let w = pack(Cursor::new(h.to_vec()), Vec::new(), &PackOptions::default(), None).unwrap();
        let (arc, _) = w.finish().unwrap();
        let mut out = Vec::new();
        unpack(Reader::new(Cursor::new(arc)).unwrap(), &mut out).unwrap();
        assert_eq!(out, h.to_vec());
    }
}

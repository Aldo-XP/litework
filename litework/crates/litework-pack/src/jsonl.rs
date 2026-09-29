//! JSON-lines ⇄ `.lwz` for records of the form
//! `{"timestamp":1787035353.906961,"bbframe":"<base64>","metadata":{...}}`
//! (DVB-S2 baseband frames carrying GSE-encapsulated IP).
//!
//! Per line: the timestamp becomes a seconds delta + fraction, the metadata
//! object is kept as text, and the frame is base64-decoded (−25% for free),
//! split into BBHEADER fields, then walked as GSE packets whose L3 payloads
//! go through the packet model. Every transform is verified to reproduce the
//! original text; lines that don't round-trip exactly are stored verbatim.

use super::packet::{find_ipv4, Layer, PacketDecoder, PacketEncoder};
use super::{Cols, PackOptions, Reader, Result, Writer, KIND_JSONL};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::io::{BufRead, Write};

pub const K_LKIND: u32 = 200;
pub const K_LRAW: u32 = 201;
pub const K_TSSEC: u32 = 202;
pub const K_TSFLEN: u32 = 204;
pub const K_META: u32 = 205;
pub const K_BBLEN: u32 = 206;
pub const K_BBKIND: u32 = 207;
pub const K_BBRAW: u32 = 208;
pub const K_BB_MATYPE: u32 = 210;
pub const K_BB_UPL: u32 = 211;
pub const K_BB_DFL: u32 = 212;
pub const K_BB_SYNC: u32 = 213;
pub const K_BB_SYNCD: u32 = 214;
pub const K_BB_CRC: u32 = 215;
pub const K_GSECNT: u32 = 216;
pub const K_GSEHDR: u32 = 217;
pub const K_GSEPRELEN: u32 = 218;
pub const K_GSEPRE: u32 = 219;
pub const K_BBPAD: u32 = 220;
pub const K_BBTAIL: u32 = 221;

pub fn col_name(key: u32) -> Option<String> {
    Some(
        match key {
            K_LKIND => "line.kind",
            K_LRAW => "line.raw",
            K_TSSEC => "ts.delta",
            K_TSFLEN => "ts.frac.len",
            K_META => "metadata",
            K_BBLEN => "bb.len",
            K_BBKIND => "bb.kind",
            K_BBRAW => "bb.raw",
            K_BB_MATYPE => "bb.matype",
            K_BB_UPL => "bb.upl",
            K_BB_DFL => "bb.dfl",
            K_BB_SYNC => "bb.sync",
            K_BB_SYNCD => "bb.syncd",
            K_BB_CRC => "bb.crc8",
            K_GSECNT => "gse.count",
            K_GSEHDR => "gse.hdr",
            K_GSEPRELEN => "gse.prefix.len",
            K_GSEPRE => "gse.prefix",
            K_BBPAD => "bb.padding",
            K_BBTAIL => "bb.tail",
            _ => return None,
        }
        .to_string(),
    )
}

const LK_RAW: u8 = 1;
const LK_NONL: u8 = 2;

/// Maximum prefix bytes searched before an IPv4 header inside a GSE body.
const GSE_MAX_PREFIX: usize = 12;
/// Prefix assumed for opaque (non-IP) GSE bodies, from observed captures:
/// 2-byte type, 6-byte label-ish field, 1 flag byte.
const GSE_OPAQUE_PREFIX: usize = 9;

const P_TS: &[u8] = b"{\"timestamp\":";
const P_BB: &[u8] = b",\"bbframe\":\"";
const P_META: &[u8] = b"\",\"metadata\":";

struct Split<'a> {
    ts: &'a [u8],
    b64: &'a [u8],
    meta: &'a [u8],
}

fn split_line(line: &[u8]) -> Option<Split<'_>> {
    let rest = line.strip_prefix(P_TS)?;
    let ts_end = rest.iter().position(|&c| c == b',')?;
    let ts = &rest[..ts_end];
    let rest = rest[ts_end..].strip_prefix(P_BB)?;
    let b64_end = rest.iter().position(|&c| c == b'"')?;
    let b64 = &rest[..b64_end];
    let rest = rest[b64_end..].strip_prefix(P_META)?;
    let meta = rest.strip_suffix(b"}")?;
    if meta.contains(&b'\n') {
        return None;
    }
    Some(Split { ts, b64, meta })
}

/// Parse `123.456` into (secs, frac, frac_digits); None if it wouldn't
/// round-trip through our formatter.
fn parse_ts(t: &[u8]) -> Option<(u64, u64, u8)> {
    let (int, frac) = match t.iter().position(|&c| c == b'.') {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    if int.is_empty() || int.len() > 18 || !int.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if int.len() > 1 && int[0] == b'0' {
        return None;
    }
    let secs: u64 = std::str::from_utf8(int).ok()?.parse().ok()?;
    match frac {
        None => Some((secs, 0, 0)),
        Some(f) => {
            if f.is_empty() || f.len() > 18 || !f.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let v: u64 = std::str::from_utf8(f).ok()?.parse().ok()?;
            Some((secs, v, f.len() as u8))
        }
    }
}

fn format_ts(out: &mut Vec<u8>, secs: u64, frac: u64, flen: u8) {
    out.extend_from_slice(secs.to_string().as_bytes());
    if flen > 0 {
        out.push(b'.');
        let s = frac.to_string();
        for _ in s.len()..flen as usize {
            out.push(b'0');
        }
        out.extend_from_slice(s.as_bytes());
    }
}

/// Timestamp as (secs, frac, digits) → a single integer at `digits`
/// precision, so successive stamps delta to small inter-arrival values.
fn ts_scaled(secs: u64, frac: u64, flen: u8, to_flen: u8) -> i128 {
    let base = secs as i128 * 10i128.pow(to_flen as u32);
    if to_flen >= flen {
        base + frac as i128 * 10i128.pow((to_flen - flen) as u32)
    } else {
        base + frac as i128 / 10i128.pow((flen - to_flen) as u32)
    }
}

fn ts_unscale(v: i128, flen: u8) -> (u64, u64) {
    let m = 10i128.pow(flen as u32);
    ((v / m) as u64, (v % m) as u64)
}

/// Why a line could not be modelled and had to be stored verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Not `{"timestamp":N,"bbframe":"B64","metadata":…}` with that exact key order.
    Shape,
    /// Timestamp isn't a plain canonical decimal (e.g. exponent, leading zero).
    Timestamp,
    /// Base64 invalid or non-canonical (would not re-encode identically).
    Base64,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Reject::Shape => "unexpected JSON shape",
            Reject::Timestamp => "non-canonical timestamp",
            Reject::Base64 => "invalid or non-canonical base64",
        })
    }
}

/// Per-line validation summary for an NDJSON pack.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub lines: u64,
    pub modelled: u64,
    pub rejected_shape: u64,
    pub rejected_timestamp: u64,
    pub rejected_base64: u64,
    /// Lines whose frame had a bad BBHEADER (DFL not a byte multiple or
    /// longer than the frame) and was stored as opaque bytes.
    pub frames_raw: u64,
    pub gse_packets: u64,
    pub gse_ipv4: u64,
    pub gse_opaque: u64,
    /// Data-field bytes left after the last parsable GSE packet (padding).
    pub padding_bytes: u64,
    /// Bytes after the data field.
    pub tail_bytes: u64,
}

impl Report {
    pub fn rejected(&self) -> u64 {
        self.rejected_shape + self.rejected_timestamp + self.rejected_base64
    }
}

struct LineEncoder {
    enc: PacketEncoder,
    prev: (u64, u64, u8),
    b64_buf: Vec<u8>,
    frame: Vec<u8>,
    report: Report,
}

impl LineEncoder {
    fn begin_block(&mut self) {
        self.enc.begin_block();
        self.prev = (0, 0, 0);
    }

    /// Encode one line; returns the reason if it had to be stored verbatim.
    fn encode(&mut self, cols: &mut Cols, line: &[u8], newline: bool) -> Option<Reject> {
        let nl_flag = if newline { 0 } else { LK_NONL };
        self.report.lines += 1;
        let reject = match self.try_model(cols, line, nl_flag) {
            Ok(()) => {
                self.report.modelled += 1;
                return None;
            }
            Err(r) => r,
        };
        match reject {
            Reject::Shape => self.report.rejected_shape += 1,
            Reject::Timestamp => self.report.rejected_timestamp += 1,
            Reject::Base64 => self.report.rejected_base64 += 1,
        }
        cols.u8(K_LKIND, LK_RAW | nl_flag);
        cols.varint(K_LRAW, line.len() as u64);
        cols.bytes(K_LRAW, line);
        Some(reject)
    }

    fn try_model(&mut self, cols: &mut Cols, line: &[u8], nl_flag: u8) -> std::result::Result<(), Reject> {
        let sp = split_line(line).ok_or(Reject::Shape)?;
        let (secs, frac, flen) = parse_ts(sp.ts).ok_or(Reject::Timestamp)?;
        self.b64_buf.clear();
        format_ts(&mut self.b64_buf, secs, frac, flen);
        if self.b64_buf != sp.ts {
            return Err(Reject::Timestamp);
        }
        let (ps, pf, pl) = self.prev;
        let delta = ts_scaled(secs, frac, flen, flen) - ts_scaled(ps, pf, pl, flen);
        if delta < i64::MIN as i128 || delta > i64::MAX as i128 {
            return Err(Reject::Timestamp);
        }
        if !self.try_frame(sp.b64) {
            return Err(Reject::Base64);
        }
        cols.u8(K_LKIND, nl_flag);
        cols.u8(K_TSFLEN, flen);
        cols.zig(K_TSSEC, delta as i64);
        self.prev = (secs, frac, flen);
        cols.bytes(K_META, sp.meta);
        cols.u8(K_META, b'\n');
        let frame = std::mem::take(&mut self.frame);
        self.encode_frame(cols, &frame);
        self.frame = frame;
        Ok(())
    }

    /// Decode base64 into `self.frame`, verifying it re-encodes identically.
    fn try_frame(&mut self, b64: &[u8]) -> bool {
        self.frame.clear();
        if B64.decode_vec(b64, &mut self.frame).is_err() {
            return false;
        }
        self.b64_buf.clear();
        B64.encode_string(&self.frame, unsafe {
            // encode_string needs a String; base64 output is pure ASCII.
            std::mem::transmute::<&mut Vec<u8>, &mut String>(&mut self.b64_buf)
        });
        self.b64_buf == b64
    }

    fn encode_frame(&mut self, cols: &mut Cols, f: &[u8]) {
        cols.varint(K_BBLEN, f.len() as u64);
        if f.len() < 10 {
            self.report.frames_raw += 1;
            cols.u8(K_BBKIND, 1);
            cols.bytes(K_BBRAW, f);
            return;
        }
        let dfl = u16::from_be_bytes([f[4], f[5]]) as usize;
        let end = 10 + dfl / 8;
        if !dfl.is_multiple_of(8) || end > f.len() {
            self.report.frames_raw += 1;
            cols.u8(K_BBKIND, 1);
            cols.bytes(K_BBRAW, f);
            return;
        }
        cols.u8(K_BBKIND, 0);
        cols.bytes(K_BB_MATYPE, &f[0..2]);
        cols.bytes(K_BB_UPL, &f[2..4]);
        cols.bytes(K_BB_DFL, &f[4..6]);
        cols.u8(K_BB_SYNC, f[6]);
        cols.bytes(K_BB_SYNCD, &f[7..9]);
        cols.u8(K_BB_CRC, f[9]);

        // GSE walk: each header's length field counts the header itself.
        let mut pos = 10;
        let mut hdrs: Vec<u8> = Vec::new();
        let mut pre_lens: Vec<u8> = Vec::new();
        let mut pres: Vec<u8> = Vec::new();
        // First pass: determine packet boundaries (so GSECNT precedes them).
        let mut bounds: Vec<(usize, usize)> = Vec::new();
        while pos + 2 <= end {
            let w = u16::from_be_bytes([f[pos], f[pos + 1]]);
            if w == 0 {
                break;
            }
            let len = (w & 0x0fff) as usize;
            if len < 2 || pos + len > end {
                break;
            }
            bounds.push((pos, pos + len));
            pos += len;
        }
        cols.varint(K_GSECNT, bounds.len() as u64);
        for (s, e) in bounds {
            hdrs.extend_from_slice(&f[s..s + 2]);
            let body = &f[s + 2..e];
            self.report.gse_packets += 1;
            let (pre, hint) = match find_ipv4(body, GSE_MAX_PREFIX) {
                Some(o) => {
                    self.report.gse_ipv4 += 1;
                    (o, None)
                }
                None => {
                    self.report.gse_opaque += 1;
                    let pre = GSE_OPAQUE_PREFIX.min(body.len());
                    let nib = body.get(pre).map(|b| b >> 4).unwrap_or(0xf) as u32;
                    (pre, Some((9 << 24) | nib))
                }
            };
            pre_lens.push(pre as u8);
            pres.extend_from_slice(&body[..pre]);
            self.enc.encode(cols, &body[pre..], Layer::RawIp, hint);
        }
        cols.bytes(K_GSEHDR, &hdrs);
        cols.bytes(K_GSEPRELEN, &pre_lens);
        cols.bytes(K_GSEPRE, &pres);
        self.report.padding_bytes += (end - pos) as u64;
        self.report.tail_bytes += (f.len() - end) as u64;
        cols.bytes(K_BBPAD, &f[pos..end]);
        cols.bytes(K_BBTAIL, &f[end..]);
    }
}

/// Pack NDJSON. With `strict`, the first line that cannot be modelled is an
/// error (naming the line number and reason) instead of being stored raw.
pub fn pack<R: BufRead, W: Write + Send + 'static>(
    mut inp: R,
    out: W,
    opts: &PackOptions,
    strict: bool,
    mut progress: Option<&mut super::pcap::Progress<'_>>,
) -> Result<(Writer<W>, Report)> {
    let mut w = Writer::new(out, KIND_JSONL, opts.clone())?;
    let mut cols = Cols::default();
    let mut le = LineEncoder {
        enc: PacketEncoder::new(),
        prev: (0, 0, 0),
        b64_buf: Vec::new(),
        frame: Vec::new(),
        report: Report::default(),
    };
    le.begin_block();
    let mut line: Vec<u8> = Vec::with_capacity(8192);
    let mut block_items = 0u64;
    let mut block_raw = 0usize;
    let mut consumed = 0u64;
    let mut lines = 0u64;
    loop {
        line.clear();
        let n = inp.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        consumed += n as u64;
        lines += 1;
        let newline = line.last() == Some(&b'\n');
        let body = if newline { &line[..line.len() - 1] } else { &line[..] };
        if let Some(why) = le.encode(&mut cols, body, newline) {
            if strict {
                return Err(super::PackError::Unsupported(format!(
                    "line {lines}: {why} (strict mode)"
                )));
            }
        }
        if strict && le.report.frames_raw > 0 {
            return Err(super::PackError::Unsupported(format!(
                "line {lines}: bbframe has an invalid BBHEADER (strict mode)"
            )));
        }
        block_items += 1;
        block_raw += n;
        if block_raw >= opts.block_bytes {
            le.enc.finish_block(&mut cols);
            w.write_block(block_items, &mut cols)?;
            le.begin_block();
            block_items = 0;
            block_raw = 0;
            if let Some(p) = progress.as_mut() {
                p(consumed, lines);
            }
        }
    }
    le.enc.finish_block(&mut cols);
    if block_items > 0 {
        w.write_block(block_items, &mut cols)?;
    }
    if let Some(p) = progress.as_mut() {
        p(consumed, lines);
    }
    Ok((w, le.report))
}

enum Part {
    Bytes(Vec<u8>),
    Pkt(usize),
}

struct Line {
    raw: Option<Vec<u8>>,
    ts: Vec<u8>,
    meta: Vec<u8>,
    parts: Vec<Part>,
    newline: bool,
}

pub fn unpack<R: std::io::Read, W: Write>(mut rd: Reader<R>, mut out: W) -> Result<u64> {
    let mut dec = PacketDecoder::new();
    let mut total = 0u64;
    while let Some((items, mut cols)) = rd.next_block()? {
        dec.begin_block();
        let mut prev: (u64, u64, u8) = (0, 0, 0);
        let mut lines: Vec<Line> = Vec::with_capacity(items as usize);
        // Pre-split the per-GSE-packet byte columns for sequential access.
        for _ in 0..items {
            let kind = cols.u8(K_LKIND)?;
            let newline = kind & LK_NONL == 0;
            if kind & LK_RAW != 0 {
                let n = cols.varint(K_LRAW)? as usize;
                let raw = cols.take(K_LRAW, n)?.to_vec();
                lines.push(Line { raw: Some(raw), ts: Vec::new(), meta: Vec::new(), parts: Vec::new(), newline });
                continue;
            }
            let flen = cols.u8(K_TSFLEN)?;
            let base = ts_scaled(prev.0, prev.1, prev.2, flen);
            let cur = base + cols.zig(K_TSSEC)? as i128;
            if cur < 0 {
                return super::fmt_err("negative timestamp in archive");
            }
            let (secs, frac) = ts_unscale(cur, flen);
            prev = (secs, frac, flen);
            let mut ts = Vec::new();
            format_ts(&mut ts, secs, frac, flen);
            let meta = {
                let c = cols.cur(K_META)?;
                let rest = &c.data[c.pos..];
                let n = rest.iter().position(|&b| b == b'\n').ok_or_else(|| {
                    super::PackError::Format("metadata column unterminated".into())
                })?;
                let m = rest[..n].to_vec();
                c.pos += n + 1;
                m
            };
            let bblen = cols.varint(K_BBLEN)? as usize;
            let mut parts = Vec::new();
            if cols.u8(K_BBKIND)? == 1 {
                parts.push(Part::Bytes(cols.take(K_BBRAW, bblen)?.to_vec()));
            } else {
                let mut h = Vec::with_capacity(10);
                h.extend_from_slice(cols.take(K_BB_MATYPE, 2)?);
                h.extend_from_slice(cols.take(K_BB_UPL, 2)?);
                h.extend_from_slice(cols.take(K_BB_DFL, 2)?);
                h.push(cols.u8(K_BB_SYNC)?);
                h.extend_from_slice(cols.take(K_BB_SYNCD, 2)?);
                h.push(cols.u8(K_BB_CRC)?);
                let dfl = u16::from_be_bytes([h[4], h[5]]) as usize;
                let end = 10 + dfl / 8;
                if end > bblen {
                    return super::fmt_err("bbframe DFL exceeds frame");
                }
                parts.push(Part::Bytes(h));
                let n = cols.varint(K_GSECNT)? as usize;
                let mut pos = 10;
                for _ in 0..n {
                    let hdr = cols.take(K_GSEHDR, 2)?.to_vec();
                    let len = (u16::from_be_bytes([hdr[0], hdr[1]]) & 0x0fff) as usize;
                    if len < 2 || pos + len > end {
                        return super::fmt_err("bad GSE length in archive");
                    }
                    let pre_len = cols.u8(K_GSEPRELEN)? as usize;
                    let body_len = len - 2;
                    if pre_len > body_len {
                        return super::fmt_err("bad GSE prefix length");
                    }
                    let mut pre = hdr;
                    pre.extend_from_slice(cols.take(K_GSEPRE, pre_len)?);
                    parts.push(Part::Bytes(pre));
                    let pkt = dec.decode(&mut cols, body_len - pre_len, Layer::RawIp)?;
                    parts.push(Part::Pkt(pkt));
                    pos += len;
                }
                parts.push(Part::Bytes(cols.take(K_BBPAD, end - pos)?.to_vec()));
                parts.push(Part::Bytes(cols.take(K_BBTAIL, bblen - end)?.to_vec()));
            }
            lines.push(Line { raw: None, ts, meta, parts, newline });
        }
        dec.resolve(&mut cols)?;
        let mut frame: Vec<u8> = Vec::with_capacity(8192);
        let mut b64 = String::with_capacity(12_000);
        for l in &lines {
            if let Some(raw) = &l.raw {
                out.write_all(raw)?;
            } else {
                frame.clear();
                for p in &l.parts {
                    match p {
                        Part::Bytes(b) => frame.extend_from_slice(b),
                        Part::Pkt(i) => dec.bytes(*i, &mut frame),
                    }
                }
                b64.clear();
                B64.encode_string(&frame, &mut b64);
                out.write_all(P_TS)?;
                out.write_all(&l.ts)?;
                out.write_all(P_BB)?;
                out.write_all(b64.as_bytes())?;
                out.write_all(P_META)?;
                out.write_all(&l.meta)?;
                out.write_all(b"}")?;
            }
            if l.newline {
                out.write_all(b"\n")?;
            }
            total += 1;
        }
    }
    out.flush()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_formats() {
        for t in ["1787035353.906961", "1787002326.4113514", "5", "0", "1.000010", "12.0"] {
            let (s, f, l) = parse_ts(t.as_bytes()).unwrap();
            let mut o = Vec::new();
            format_ts(&mut o, s, f, l);
            assert_eq!(o, t.as_bytes());
        }
        assert!(parse_ts(b"01.5").is_none());
        assert!(parse_ts(b"1e5").is_none());
        assert!(parse_ts(b"-1").is_none());
        assert!(parse_ts(b"1.").is_none());
    }

    #[test]
    fn split_ok() {
        let l = br#"{"timestamp":1.5,"bbframe":"AAAA","metadata":{"a":1}}"#;
        let s = split_line(l).unwrap();
        assert_eq!(s.ts, b"1.5");
        assert_eq!(s.b64, b"AAAA");
        assert_eq!(s.meta, br#"{"a":1}"#);
        assert!(split_line(b"{\"x\":1}").is_none());
    }
}

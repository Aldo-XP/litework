//! Packet model: shreds Ethernet/IPv4/TCP/UDP headers into per-field columns,
//! predicting each field from per-flow state so most residuals are zero, and
//! routes payloads into per-class columns grouped by flow.
//!
//! The encoder and decoder share the flow-state update logic, so the
//! decoder reproduces every prediction exactly. Anything that does not parse
//! falls back to raw bytes; nothing is ever lost.
//!
//! Per packet the encoder emits (in column order):
//!   KIND            0 raw · 1 L2 only · 2 IPv4 · 3 IPv4+TCP · 4 IPv4+UDP
//!   FLOWCODE        MTF position of the flow, 254 = index follows, 255 = new
//!   [FLOWIDX]       varint flow index (code 254)
//!   [FLOWDEF]       u8 len + key bytes (code 255)
//!   [CLASSKEY]      varint payload class (kind 1)
//!   IPv4 fields, L4 fields, then payload → class column
//!
//! The flow key is `l2_bytes ++ [src4, dst4, proto, sport, dport]` for IP
//! kinds and just `l2_bytes` for kind 1, so a key's length tells the decoder
//! how many L2 bytes to replay.

use super::{ColReaders, Cols, Result};
use std::collections::{HashMap, VecDeque};

pub const K_KIND: u32 = 1;
pub const K_FLOWCODE: u32 = 2;
pub const K_FLOWIDX: u32 = 3;
pub const K_FLOWDEF: u32 = 4;
pub const K_CLASSKEY: u32 = 5;
pub const K_RAWPKT: u32 = 6;
pub const K_VIHL: u32 = 10;
pub const K_TOS: u32 = 11;
pub const K_TOTLEN: u32 = 12;
pub const K_IPID: u32 = 13;
pub const K_FRAG: u32 = 14;
pub const K_TTL: u32 = 15;
pub const K_IPCK: u32 = 16;
pub const K_IPOPTS: u32 = 17;
pub const K_SEQ: u32 = 20;
pub const K_ACK: u32 = 21;
pub const K_TFLAGS: u32 = 22;
pub const K_WIN: u32 = 23;
pub const K_TCK: u32 = 24;
pub const K_URG: u32 = 25;
pub const K_TOPTS: u32 = 26;
pub const K_ULEN: u32 = 30;
pub const K_UCK: u32 = 31;
/// Payload class columns: `K_CLASS_BASE | class`.
pub const K_CLASS_BASE: u32 = 0x1000_0000;

pub fn col_name(key: u32) -> Option<String> {
    let n = match key {
        K_KIND => "pkt.kind",
        K_FLOWCODE => "pkt.flowcode",
        K_FLOWIDX => "pkt.flowidx",
        K_FLOWDEF => "pkt.flowdef",
        K_CLASSKEY => "pkt.classkey",
        K_RAWPKT => "pkt.raw",
        K_VIHL => "ip.vihl",
        K_TOS => "ip.tos",
        K_TOTLEN => "ip.totlen.res",
        K_IPID => "ip.id.delta",
        K_FRAG => "ip.frag",
        K_TTL => "ip.ttl",
        K_IPCK => "ip.cksum.res",
        K_IPOPTS => "ip.opts",
        K_SEQ => "tcp.seq.delta",
        K_ACK => "tcp.ack.delta",
        K_TFLAGS => "tcp.flags",
        K_WIN => "tcp.win",
        K_TCK => "tcp.cksum.res",
        K_URG => "tcp.urg",
        K_TOPTS => "tcp.opts",
        K_ULEN => "udp.len.res",
        K_UCK => "udp.cksum.res",
        k if k & K_CLASS_BASE != 0 => {
            let c = k & !K_CLASS_BASE;
            return Some(match c >> 24 {
                1 => format!("payload.l2.et{:#06x}.n{:x}", (c >> 4) & 0xffff, c & 0xf),
                2 => format!("payload.ip.proto{}", c & 0xff),
                3 => format!("payload.tcp.port{}", c & 0xffff),
                4 => format!("payload.udp.port{}", c & 0xffff),
                9 => format!("payload.opaque.n{:x}", c & 0xffff),
                _ => format!("payload.{c:#x}"),
            });
        }
        _ => return None,
    };
    Some(n.to_string())
}

const KIND_RAW: u8 = 0;
const KIND_L2: u8 = 1;
const KIND_IP: u8 = 2;
const KIND_TCP: u8 = 3;
const KIND_UDP: u8 = 4;

const MTF_CAP: usize = 254;

/// How the packet bytes begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Ethernet II (+ optional 802.1Q/ad tags).
    Ethernet,
    /// Starts directly at the IP header.
    RawIp,
    /// Not modelled: stored verbatim.
    Opaque,
}

#[derive(Default, Clone)]
struct FlowState {
    last_id: u16,
    pred_seq: u32,
    last_ack: u32,
}

/// Parsed view of one packet (encoder side).
struct Parsed {
    kind: u8,
    l2_len: usize,
    ethertype: u16,
    ihl: usize,
    totlen: u16,
    proto: u8,
    l4_len: usize,
    sport: u16,
    dport: u16,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn ones_sum(b: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < b.len() {
        acc += be16(&b[i..]) as u32;
        i += 2;
    }
    if i < b.len() {
        acc += (b[i] as u32) << 8;
    }
    acc
}
fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// IPv4 header checksum with the checksum field treated as zero.
fn ip_checksum(hdr: &[u8]) -> u16 {
    let s = ones_sum(&hdr[..10], 0);
    let s = ones_sum(&hdr[12..], s);
    fold(s)
}

/// Checksum that an IPv4-like header would have if its version nibble were 4
/// (some middleboxes rewrite the nibble without fixing the checksum).
fn ip_checksum_v4(hdr: &[u8]) -> u16 {
    let mut h = [0u8; 60];
    let n = hdr.len().min(60);
    h[..n].copy_from_slice(&hdr[..n]);
    h[0] = 0x40 | (h[0] & 0x0f);
    ip_checksum(&h[..n])
}

/// TCP/UDP checksum over the IPv4 pseudo-header + segment, with the segment's
/// own checksum field (at `ck_off`) treated as zero.
fn l4_checksum(src: &[u8], dst: &[u8], proto: u8, seg: &[u8], ck_off: usize) -> u16 {
    let mut s = ones_sum(src, 0);
    s = ones_sum(dst, s);
    s += proto as u32;
    s += seg.len() as u32;
    s = ones_sum(&seg[..ck_off], s);
    s = ones_sum(&seg[ck_off + 2..], s);
    fold(s)
}

/// Does `b` look like an IPv4 header we can model? Tolerates a rewritten
/// version nibble when the checksum proves the header is otherwise intact.
pub fn looks_like_ipv4(b: &[u8]) -> bool {
    if b.len() < 20 {
        return false;
    }
    let ihl = (b[0] & 0x0f) as usize * 4;
    if !(20..=60).contains(&ihl) || ihl > b.len() {
        return false;
    }
    let totlen = be16(&b[2..]) as usize;
    if totlen < ihl {
        return false;
    }
    let ver = b[0] >> 4;
    if ver == 4 {
        return true;
    }
    let hdr = &b[..ihl];
    let ck = be16(&b[10..]);
    ip_checksum(hdr) == ck || ip_checksum_v4(hdr) == ck
}

/// Find an IPv4 header within the first `max_off` bytes of `body`, for
/// framings that put a variable prefix before the L3 packet. Stricter than
/// `looks_like_ipv4`: the header must prove itself via checksum or an exact
/// length match, so random bytes rarely pass.
pub fn find_ipv4(body: &[u8], max_off: usize) -> Option<usize> {
    for o in 0..=max_off.min(body.len()) {
        let b = &body[o..];
        if b.len() < 20 || !looks_like_ipv4(b) {
            continue;
        }
        let ihl = (b[0] & 0x0f) as usize * 4;
        let totlen = be16(&b[2..]) as usize;
        if totlen > b.len() {
            continue;
        }
        let ck = be16(&b[10..]);
        if totlen == b.len() || ip_checksum(&b[..ihl]) == ck || ip_checksum_v4(&b[..ihl]) == ck {
            return Some(o);
        }
    }
    None
}

fn parse(data: &[u8], layer: Layer) -> Parsed {
    let mut p = Parsed {
        kind: KIND_RAW,
        l2_len: 0,
        ethertype: 0,
        ihl: 0,
        totlen: 0,
        proto: 0,
        l4_len: 0,
        sport: 0,
        dport: 0,
    };
    let ip_start = match layer {
        Layer::Opaque => return p,
        Layer::RawIp => 0,
        Layer::Ethernet => {
            if data.len() < 14 {
                return p;
            }
            let mut off = 12;
            let mut et = be16(&data[off..]);
            let mut tags = 0;
            while (et == 0x8100 || et == 0x88a8 || et == 0x9100) && data.len() >= off + 6 && tags < 3 {
                off += 4;
                tags += 1;
                et = be16(&data[off..]);
            }
            p.l2_len = off + 2;
            p.ethertype = et;
            p.kind = KIND_L2;
            if et != 0x0800 {
                return p;
            }
            p.l2_len
        }
    };
    let ip = &data[ip_start..];
    if !looks_like_ipv4(ip) {
        if layer == Layer::RawIp {
            // Not IP, but still worth a flow-grouped class column.
            p.kind = KIND_L2;
        }
        return p;
    }
    p.kind = KIND_IP;
    p.ihl = (ip[0] & 0x0f) as usize * 4;
    p.totlen = be16(&ip[2..]);
    p.proto = ip[9];
    let l4 = &ip[p.ihl..];
    match p.proto {
        6 if l4.len() >= 20 => {
            let doff = (l4[12] >> 4) as usize * 4;
            if (20..=60).contains(&doff) && doff <= l4.len() {
                p.kind = KIND_TCP;
                p.l4_len = doff;
                p.sport = be16(l4);
                p.dport = be16(&l4[2..]);
            }
        }
        17 if l4.len() >= 8 => {
            p.kind = KIND_UDP;
            p.l4_len = 8;
            p.sport = be16(l4);
            p.dport = be16(&l4[2..]);
        }
        _ => {}
    }
    p
}

fn payload_class(kind: u8, ethertype: u16, first: u8, proto: u8, sport: u16, dport: u16) -> u32 {
    match kind {
        // Non-IP: by ethertype; for "IPv4" frames that aren't, also by the
        // first nibble (separates tunnelled/proprietary framings).
        KIND_L2 => {
            let nib = if ethertype == 0x0800 { (first >> 4) as u32 } else { 0 };
            (1 << 24) | ((ethertype as u32) << 4) | nib
        }
        KIND_IP => (2 << 24) | proto as u32,
        KIND_TCP | KIND_UDP => {
            let lo = sport.min(dport);
            let port = if lo < 1024 { lo as u32 } else { 0xffff };
            ((kind as u32) << 24) | port
        }
        _ => 0,
    }
}

/// Per-block payload buffers: class → flows in first-seen order → bytes.
#[derive(Default)]
struct ClassBuf {
    order: Vec<u32>,
    bufs: HashMap<u32, Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct PacketEncoder {
    flows: HashMap<Vec<u8>, u32>,
    states: Vec<FlowState>,
    mtf: VecDeque<u32>,
    classes: HashMap<u32, ClassBuf>,
    class_order: Vec<u32>,
    key_buf: Vec<u8>,
}

impl PacketEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset per-block state (flow table, payload buffers).
    pub fn begin_block(&mut self) {
        self.flows.clear();
        self.states.clear();
        self.mtf.clear();
        self.classes.clear();
        self.class_order.clear();
    }

    fn flow_code(&mut self, cols: &mut Cols) -> u32 {
        let key = &self.key_buf;
        if let Some(&idx) = self.flows.get(key) {
            if let Some(pos) = self.mtf.iter().position(|&f| f == idx) {
                cols.u8(K_FLOWCODE, pos as u8);
                self.mtf.remove(pos);
            } else {
                cols.u8(K_FLOWCODE, 254);
                cols.varint(K_FLOWIDX, idx as u64);
            }
            self.mtf.push_front(idx);
            self.mtf.truncate(MTF_CAP);
            idx
        } else {
            let idx = self.states.len() as u32;
            self.flows.insert(key.clone(), idx);
            self.states.push(FlowState::default());
            cols.u8(K_FLOWCODE, 255);
            cols.u8(K_FLOWDEF, key.len() as u8);
            cols.bytes(K_FLOWDEF, key);
            self.mtf.push_front(idx);
            self.mtf.truncate(MTF_CAP);
            idx
        }
    }

    fn push_payload(&mut self, class: u32, flow: u32, bytes: &[u8]) {
        let cb = match self.classes.get_mut(&class) {
            Some(cb) => cb,
            None => {
                self.class_order.push(class);
                self.classes.entry(class).or_default()
            }
        };
        let buf = match cb.bufs.get_mut(&flow) {
            Some(b) => b,
            None => {
                cb.order.push(flow);
                cb.bufs.entry(flow).or_default()
            }
        };
        buf.extend_from_slice(bytes);
    }

    /// Encode one packet. `class_hint` overrides the payload class for
    /// non-IP packets (callers that know more about the framing).
    pub fn encode(&mut self, cols: &mut Cols, data: &[u8], layer: Layer, class_hint: Option<u32>) {
        let p = parse(data, layer);
        cols.u8(K_KIND, p.kind);
        if p.kind == KIND_RAW {
            cols.bytes(K_RAWPKT, data);
            return;
        }
        // Flow key.
        self.key_buf.clear();
        self.key_buf.extend_from_slice(&data[..p.l2_len]);
        let ip = &data[p.l2_len..];
        if p.kind >= KIND_IP {
            self.key_buf.extend_from_slice(&ip[12..20]);
            self.key_buf.push(p.proto);
            self.key_buf.extend_from_slice(&p.sport.to_be_bytes());
            self.key_buf.extend_from_slice(&p.dport.to_be_bytes());
        }
        let flow = self.flow_code(cols);

        if p.kind == KIND_L2 {
            let first = ip.first().copied().unwrap_or(0);
            let class = class_hint.unwrap_or_else(|| payload_class(KIND_L2, p.ethertype, first, 0, 0, 0));
            cols.varint(K_CLASSKEY, class as u64);
            self.push_payload(class, flow, ip);
            return;
        }

        // IPv4 header.
        let st = &mut self.states[flow as usize];
        cols.u8(K_VIHL, ip[0]);
        cols.u8(K_TOS, ip[1]);
        cols.zig(K_TOTLEN, p.totlen as i64 - ip.len() as i64);
        let id = be16(&ip[4..]);
        cols.zig(K_IPID, id.wrapping_sub(st.last_id) as i16 as i64);
        st.last_id = id;
        cols.bytes(K_FRAG, &ip[6..8]);
        cols.u8(K_TTL, ip[8]);
        let ck = be16(&ip[10..]);
        cols.u16(K_IPCK, ck.wrapping_sub(ip_checksum(&ip[..p.ihl])));
        if p.ihl > 20 {
            cols.bytes(K_IPOPTS, &ip[20..p.ihl]);
        }
        let l4 = &ip[p.ihl..];
        let declared = (p.totlen as usize).saturating_sub(p.ihl);
        let seg_len = if declared <= l4.len() { declared } else { l4.len() };
        let seg = &l4[..seg_len];

        match p.kind {
            KIND_TCP => {
                let seq = be32(&l4[4..]);
                let ack = be32(&l4[8..]);
                cols.zig(K_SEQ, seq.wrapping_sub(st.pred_seq) as i32 as i64);
                cols.zig(K_ACK, ack.wrapping_sub(st.last_ack) as i32 as i64);
                cols.bytes(K_TFLAGS, &l4[12..14]);
                cols.bytes(K_WIN, &l4[14..16]);
                let ck = be16(&l4[16..]);
                cols.u16(K_TCK, ck.wrapping_sub(l4_checksum(&ip[12..16], &ip[16..20], 6, seg, 16)));
                cols.bytes(K_URG, &l4[18..20]);
                if p.l4_len > 20 {
                    cols.bytes(K_TOPTS, &l4[20..p.l4_len]);
                }
                let flags = l4[13];
                let adv = seg_len.saturating_sub(p.l4_len) as u32
                    + (flags & 0x02 != 0) as u32
                    + (flags & 0x01 != 0) as u32;
                st.pred_seq = seq.wrapping_add(adv);
                st.last_ack = ack;
            }
            KIND_UDP => {
                cols.zig(K_ULEN, be16(&l4[4..]) as i64 - declared as i64);
                let ck = be16(&l4[6..]);
                cols.u16(K_UCK, ck.wrapping_sub(l4_checksum(&ip[12..16], &ip[16..20], 17, seg, 6)));
            }
            _ => {}
        }
        let class = payload_class(p.kind, 0, 0, p.proto, p.sport, p.dport);
        let payload = &l4[p.l4_len..];
        self.push_payload(class, flow, payload);
    }

    /// Flush payload buffers into their class columns (call once per block,
    /// after the last packet).
    pub fn finish_block(&mut self, cols: &mut Cols) {
        for class in self.class_order.drain(..) {
            let cb = self.classes.remove(&class).unwrap();
            let col = cols.col(K_CLASS_BASE | class);
            for flow in cb.order {
                col.extend_from_slice(&cb.bufs[&flow]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// One decoded packet header plus where its payload lives.
struct Pending {
    head: Vec<u8>,
    class: u32,
    flow: u32,
    pay_len: usize,
    /// Resolved offset into the class column (after `resolve`).
    pay_off: usize,
    raw: bool,
}

#[derive(Default)]
pub struct PacketDecoder {
    defs: Vec<Vec<u8>>,
    states: Vec<FlowState>,
    mtf: VecDeque<u32>,
    pending: Vec<Pending>,
    class_data: HashMap<u32, Vec<u8>>,
    ck_fix: Vec<CkFix>,
}

impl PacketDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_block(&mut self) {
        self.defs.clear();
        self.states.clear();
        self.mtf.clear();
        self.pending.clear();
        self.class_data.clear();
        self.ck_fix.clear();
    }

    fn flow_decode(&mut self, cols: &mut ColReaders) -> Result<u32> {
        let code = cols.u8(K_FLOWCODE)?;
        let idx = match code {
            255 => {
                let n = cols.u8(K_FLOWDEF)? as usize;
                let key = cols.take(K_FLOWDEF, n)?.to_vec();
                self.defs.push(key);
                self.states.push(FlowState::default());
                (self.defs.len() - 1) as u32
            }
            254 => {
                let idx = cols.varint(K_FLOWIDX)? as u32;
                if idx as usize >= self.defs.len() {
                    return super::fmt_err("flow index out of range");
                }
                if let Some(pos) = self.mtf.iter().position(|&f| f == idx) {
                    self.mtf.remove(pos);
                }
                idx
            }
            pos => {
                let pos = pos as usize;
                if pos >= self.mtf.len() {
                    return super::fmt_err("flow MTF position out of range");
                }
                self.mtf.remove(pos).unwrap()
            }
        };
        self.mtf.push_front(idx);
        self.mtf.truncate(MTF_CAP);
        Ok(idx)
    }

    /// Decode one packet's headers. Payload bytes are attached later by
    /// `resolve`; the packet's index is returned.
    pub fn decode(&mut self, cols: &mut ColReaders, total_len: usize, layer: Layer) -> Result<usize> {
        let kind = cols.u8(K_KIND)?;
        if kind == KIND_RAW {
            let head = cols.take(K_RAWPKT, total_len)?.to_vec();
            self.pending.push(Pending { head, class: 0, flow: 0, pay_len: 0, pay_off: 0, raw: true });
            return Ok(self.pending.len() - 1);
        }
        let flow = self.flow_decode(cols)?;
        let key = &self.defs[flow as usize];
        let l2_len = match (layer, kind) {
            (Layer::Ethernet, KIND_L2) => key.len(),
            (Layer::Ethernet, _) => key.len().checked_sub(13).ok_or_else(|| {
                super::PackError::Format("flow key too short".into())
            })?,
            _ => 0,
        };
        if l2_len > key.len() || l2_len > total_len {
            return super::fmt_err("inconsistent flow key");
        }
        let mut head: Vec<u8> = Vec::with_capacity(80);
        head.extend_from_slice(&key[..l2_len]);
        if kind == KIND_L2 {
            let class = cols.varint(K_CLASSKEY)? as u32;
            let pay_len = total_len - l2_len;
            self.pending.push(Pending { head, class, flow, pay_len, pay_off: 0, raw: false });
            return Ok(self.pending.len() - 1);
        }
        let tuple = &key[l2_len..];
        if tuple.len() != 13 {
            return super::fmt_err("bad IP flow key");
        }
        let (src, dst, proto) = (&tuple[0..4], &tuple[4..8], tuple[8]);
        let sport = &tuple[9..11];
        let dport = &tuple[11..13];
        let st = &mut self.states[flow as usize];
        let ip_avail = total_len - l2_len;

        let vihl = cols.u8(K_VIHL)?;
        let ihl = (vihl & 0x0f) as usize * 4;
        let tos = cols.u8(K_TOS)?;
        let totlen = (cols.zig(K_TOTLEN)? + ip_avail as i64) as u16;
        let id = st.last_id.wrapping_add(cols.zig(K_IPID)? as i16 as u16);
        st.last_id = id;
        let frag = cols.take(K_FRAG, 2)?.to_vec();
        let ttl = cols.u8(K_TTL)?;
        let ck_res = cols.u16(K_IPCK)?;
        let ip_start = head.len();
        head.push(vihl);
        head.push(tos);
        head.extend_from_slice(&totlen.to_be_bytes());
        head.extend_from_slice(&id.to_be_bytes());
        head.extend_from_slice(&frag);
        head.push(ttl);
        head.push(proto);
        head.extend_from_slice(&[0, 0]);
        head.extend_from_slice(src);
        head.extend_from_slice(dst);
        if ihl > 20 {
            let opts = cols.take(K_IPOPTS, ihl - 20)?.to_vec();
            head.extend_from_slice(&opts);
        }
        if ihl < 20 || ihl > ip_avail {
            return super::fmt_err("bad IHL");
        }
        let ck = ip_checksum(&head[ip_start..]).wrapping_add(ck_res);
        head[ip_start + 10..ip_start + 12].copy_from_slice(&ck.to_be_bytes());

        let l4_avail = ip_avail - ihl;
        let declared = (totlen as usize).saturating_sub(ihl);
        let seg_len = if declared <= l4_avail { declared } else { l4_avail };
        let l4_start = head.len();
        let (l4_len, class) = match kind {
            KIND_TCP => {
                let seq = st.pred_seq.wrapping_add(cols.zig(K_SEQ)? as i32 as u32);
                let ack = st.last_ack.wrapping_add(cols.zig(K_ACK)? as i32 as u32);
                let flags = cols.take(K_TFLAGS, 2)?.to_vec();
                let win = cols.take(K_WIN, 2)?.to_vec();
                let ck_res = cols.u16(K_TCK)?;
                let urg = cols.take(K_URG, 2)?.to_vec();
                let doff = (flags[0] >> 4) as usize * 4;
                if !(20..=60).contains(&doff) || doff > l4_avail {
                    return super::fmt_err("bad TCP data offset");
                }
                head.extend_from_slice(sport);
                head.extend_from_slice(dport);
                head.extend_from_slice(&seq.to_be_bytes());
                head.extend_from_slice(&ack.to_be_bytes());
                head.extend_from_slice(&flags);
                head.extend_from_slice(&win);
                head.extend_from_slice(&[0, 0]);
                head.extend_from_slice(&urg);
                if doff > 20 {
                    let opts = cols.take(K_TOPTS, doff - 20)?.to_vec();
                    head.extend_from_slice(&opts);
                }
                let adv = seg_len.saturating_sub(doff) as u32
                    + (flags[1] & 0x02 != 0) as u32
                    + (flags[1] & 0x01 != 0) as u32;
                st.pred_seq = seq.wrapping_add(adv);
                st.last_ack = ack;
                // Checksum needs the payload; patched in `resolve`.
                self.ck_fix.push(CkFix {
                    pkt: self.pending.len(),
                    ip_start,
                    l4_start,
                    seg_len,
                    ck_off: 16,
                    proto: 6,
                    res: ck_res,
                });
                (doff, payload_class(KIND_TCP, 0, 0, 6, be16(sport), be16(dport)))
            }
            KIND_UDP => {
                if l4_avail < 8 {
                    return super::fmt_err("UDP header truncated");
                }
                let ulen = (cols.zig(K_ULEN)? + declared as i64) as u16;
                let ck_res = cols.u16(K_UCK)?;
                head.extend_from_slice(sport);
                head.extend_from_slice(dport);
                head.extend_from_slice(&ulen.to_be_bytes());
                head.extend_from_slice(&[0, 0]);
                self.ck_fix.push(CkFix {
                    pkt: self.pending.len(),
                    ip_start,
                    l4_start,
                    seg_len,
                    ck_off: 6,
                    proto: 17,
                    res: ck_res,
                });
                (8, payload_class(KIND_UDP, 0, 0, 17, be16(sport), be16(dport)))
            }
            KIND_IP => (0, payload_class(KIND_IP, 0, 0, proto, 0, 0)),
            _ => return super::fmt_err("unknown packet kind"),
        };
        let pay_len = l4_avail - l4_len;
        self.pending.push(Pending { head, class, flow, pay_len, pay_off: 0, raw: false });
        Ok(self.pending.len() - 1)
    }

    /// After all packets of a block are decoded: lay out payload slices and
    /// patch L4 checksums. Must be called before `bytes`.
    pub fn resolve(&mut self, cols: &mut ColReaders) -> Result<()> {
        // Per class: flows in first-seen order, each flow's payloads in
        // packet order — mirror of PacketEncoder::finish_block.
        let mut per_class: HashMap<u32, (Vec<u32>, HashMap<u32, usize>)> = HashMap::new();
        for p in &self.pending {
            if p.raw {
                continue;
            }
            let e = per_class.entry(p.class).or_default();
            match e.1.get_mut(&p.flow) {
                Some(t) => *t += p.pay_len,
                None => {
                    e.0.push(p.flow);
                    e.1.insert(p.flow, p.pay_len);
                }
            }
        }
        let mut base: HashMap<(u32, u32), usize> = HashMap::new();
        for (class, (order, totals)) in &per_class {
            let mut off = 0;
            for f in order {
                base.insert((*class, *f), off);
                off += totals[f];
            }
            let data = cols.rest(K_CLASS_BASE | class);
            if data.len() != off {
                return super::fmt_err(format!(
                    "payload class {class:#x} length mismatch ({} vs {off})",
                    data.len()
                ));
            }
            self.class_data.insert(*class, data);
        }
        for p in &mut self.pending {
            if p.raw {
                continue;
            }
            let b = base.get_mut(&(p.class, p.flow)).unwrap();
            p.pay_off = *b;
            *b += p.pay_len;
        }
        // L4 checksums: compute over header + payload, add residual.
        for fx in self.ck_fix.drain(..) {
            let p = &mut self.pending[fx.pkt];
            let pay = &self.class_data[&p.class][p.pay_off..p.pay_off + p.pay_len];
            let mut seg = Vec::with_capacity(fx.seg_len);
            seg.extend_from_slice(&p.head[fx.l4_start..]);
            seg.extend_from_slice(pay);
            seg.truncate(fx.seg_len);
            let ip = &p.head[fx.ip_start..];
            let ck = l4_checksum(&ip[12..16], &ip[16..20], fx.proto, &seg, fx.ck_off).wrapping_add(fx.res);
            let o = fx.l4_start + fx.ck_off;
            p.head[o..o + 2].copy_from_slice(&ck.to_be_bytes());
        }
        Ok(())
    }

    /// Append the full bytes of decoded packet `i` to `out`.
    pub fn bytes(&self, i: usize, out: &mut Vec<u8>) {
        let p = &self.pending[i];
        out.extend_from_slice(&p.head);
        if !p.raw && p.pay_len > 0 {
            out.extend_from_slice(&self.class_data[&p.class][p.pay_off..p.pay_off + p.pay_len]);
        }
    }
}

struct CkFix {
    pkt: usize,
    ip_start: usize,
    l4_start: usize,
    seg_len: usize,
    ck_off: usize,
    proto: u8,
    res: u16,
}


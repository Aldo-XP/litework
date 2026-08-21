//! Filter language + execution.
//!
//! Grammar:
//!   expr  := or
//!   or    := and ("||" and)*
//!   and   := unary ("&&" unary)*
//!   unary := "!" unary | "(" expr ")" | cmp
//!   cmp   := field op value | field "in" "{" value ("," value)* "}"
//!   op    := == != < > <= >=
//!
//! Fields: mac, mac_src, mac_dst, ip, ip_src, ip_dst, proto, port, sport,
//!         dport, ethertype, vlan, len
//! Values:
//!   MAC       aa:bb:cc:dd:ee:ff, wildcard bytes aa:bb:*:*:*:01, prefix aa:bb:*
//!   IPv4      10.0.0.1, wildcard octets 10.10.*.180, prefix 10.10.*,
//!             CIDR 10.10.0.0/16
//!   IPv6      full addresses and CIDR fe80::/10
//!   ports &c  numbers (dec or 0x hex) and ranges 5900-5910
//!   proto     tcp, udp, icmp, arp, ... or an IP protocol number
//!
//! Execution prunes tier-0 row groups (never a false negative), then scans
//! only surviving regions — from the column sidecar when present, otherwise
//! by rescanning the capture.

use crate::format::{FormatError, PcapFile};
use crate::index::{CaptureIndex, MacDict, RowGroup};
use crate::types::*;

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("filter error: {0}")]
pub struct ParseError(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    MacAny,
    MacSrc,
    MacDst,
    IpAny,
    IpSrc,
    IpDst,
    Proto,
    PortAny,
    Sport,
    Dport,
    Ethertype,
    Vlan,
    Len,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

/// A typed comparison value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Mac([u8; 6]),
    /// Wildcarded MAC: matches when `addr & mask == pat`.
    MacMask { pat: [u8; 6], mask: [u8; 6] },
    Ip4([u8; 4]),
    /// Wildcarded/CIDR IPv4: matches when `addr & mask == pat`.
    Ip4Mask { pat: [u8; 4], mask: [u8; 4] },
    Ip6([u8; 16]),
    Ip6Mask { pat: [u8; 16], mask: [u8; 16] },
    /// IP protocol number (tcp, udp, ... or bare number for `proto`).
    ProtoIp(u8),
    /// Ethertype-level protocol (arp, ipv4, ipv6, lldp, ...).
    ProtoEther(u16),
    Num(u64),
    /// Inclusive numeric range `lo-hi`.
    NumRange(u64, u64),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Cmp(Field, CmpOp, Value),
    In(Field, Vec<Value>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

// ---------------------------------------------------------------- parsing

struct Lexer<'a> {
    s: &'a str,
    pos: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Op(&'static str),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    End,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Lexer { s, pos: 0 }
    }

    fn next(&mut self) -> Result<Tok, ParseError> {
        let b = self.s.as_bytes();
        while self.pos < b.len() && (b[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
        if self.pos >= b.len() {
            return Ok(Tok::End);
        }
        let rest = &self.s[self.pos..];
        for (pat, tok) in [
            ("==", Tok::Op("==")),
            ("!=", Tok::Op("!=")),
            ("<=", Tok::Op("<=")),
            (">=", Tok::Op(">=")),
            ("&&", Tok::Op("&&")),
            ("||", Tok::Op("||")),
            ("<", Tok::Op("<")),
            (">", Tok::Op(">")),
            ("!", Tok::Op("!")),
            ("(", Tok::LParen),
            (")", Tok::RParen),
            ("{", Tok::LBrace),
            ("}", Tok::RBrace),
            (",", Tok::Comma),
        ] {
            if rest.starts_with(pat) {
                self.pos += pat.len();
                return Ok(tok);
            }
        }
        // Identifier / literal: letters, digits, MAC/IP/wildcard punctuation.
        let start = self.pos;
        while self.pos < b.len() {
            let c = b[self.pos] as char;
            if c.is_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | 'x' | '*' | '/') {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(ParseError(format!(
                "unexpected character '{}' at {}",
                rest.chars().next().unwrap(),
                self.pos
            )));
        }
        Ok(Tok::Ident(self.s[start..self.pos].to_string()))
    }

    fn peek(&mut self) -> Result<Tok, ParseError> {
        let save = self.pos;
        let t = self.next()?;
        self.pos = save;
        Ok(t)
    }
}

pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let mut lx = Lexer::new(input);
    let e = parse_or(&mut lx)?;
    match lx.next()? {
        Tok::End => Ok(e),
        t => Err(ParseError(format!("unexpected trailing token {t:?}"))),
    }
}

fn parse_or(lx: &mut Lexer) -> Result<Expr, ParseError> {
    let mut left = parse_and(lx)?;
    while lx.peek()? == Tok::Op("||") {
        lx.next()?;
        let right = parse_and(lx)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(lx: &mut Lexer) -> Result<Expr, ParseError> {
    let mut left = parse_unary(lx)?;
    while lx.peek()? == Tok::Op("&&") {
        lx.next()?;
        let right = parse_unary(lx)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_unary(lx: &mut Lexer) -> Result<Expr, ParseError> {
    match lx.peek()? {
        Tok::Op("!") => {
            lx.next()?;
            Ok(Expr::Not(Box::new(parse_unary(lx)?)))
        }
        Tok::LParen => {
            lx.next()?;
            let e = parse_or(lx)?;
            match lx.next()? {
                Tok::RParen => Ok(e),
                t => Err(ParseError(format!("expected ')', got {t:?}"))),
            }
        }
        _ => parse_cmp(lx),
    }
}

fn parse_cmp(lx: &mut Lexer) -> Result<Expr, ParseError> {
    let field = match lx.next()? {
        Tok::Ident(name) => parse_field(&name)?,
        t => return Err(ParseError(format!("expected field name, got {t:?}"))),
    };
    match lx.next()? {
        Tok::Op(op @ ("==" | "!=" | "<" | ">" | "<=" | ">=")) => {
            let op = match op {
                "==" => CmpOp::Eq,
                "!=" => CmpOp::Ne,
                "<" => CmpOp::Lt,
                ">" => CmpOp::Gt,
                "<=" => CmpOp::Le,
                _ => CmpOp::Ge,
            };
            let v = match lx.next()? {
                Tok::Ident(s) => parse_value(field, &s)?,
                t => return Err(ParseError(format!("expected value, got {t:?}"))),
            };
            if !matches!(op, CmpOp::Eq | CmpOp::Ne) && !matches!(v, Value::Num(_)) {
                return Err(ParseError(
                    "ordering operators need a plain numeric value".into(),
                ));
            }
            Ok(Expr::Cmp(field, op, v))
        }
        Tok::Ident(kw) if kw == "in" => {
            match lx.next()? {
                Tok::LBrace => {}
                t => return Err(ParseError(format!("expected '{{' after in, got {t:?}"))),
            }
            let mut vals = Vec::new();
            loop {
                match lx.next()? {
                    Tok::Ident(s) => vals.push(parse_value(field, &s)?),
                    Tok::RBrace if !vals.is_empty() => break,
                    t => return Err(ParseError(format!("expected value, got {t:?}"))),
                }
                match lx.next()? {
                    Tok::Comma => continue,
                    Tok::RBrace => break,
                    t => return Err(ParseError(format!("expected ',' or '}}', got {t:?}"))),
                }
            }
            Ok(Expr::In(field, vals))
        }
        t => Err(ParseError(format!("expected operator, got {t:?}"))),
    }
}

fn parse_field(name: &str) -> Result<Field, ParseError> {
    Ok(match name {
        "mac" => Field::MacAny,
        "mac_src" | "mac.src" => Field::MacSrc,
        "mac_dst" | "mac.dst" => Field::MacDst,
        "ip" => Field::IpAny,
        "ip_src" | "ip.src" | "src" => Field::IpSrc,
        "ip_dst" | "ip.dst" | "dst" => Field::IpDst,
        "proto" | "protocol" => Field::Proto,
        "port" => Field::PortAny,
        "sport" | "port.src" => Field::Sport,
        "dport" | "port.dst" => Field::Dport,
        "ethertype" => Field::Ethertype,
        "vlan" => Field::Vlan,
        "len" | "length" => Field::Len,
        other => return Err(ParseError(format!("unknown field '{other}'"))),
    })
}

fn parse_num(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Number or inclusive range `lo-hi` (order-normalized).
fn parse_num_or_range(s: &str) -> Option<Value> {
    if let Some(n) = parse_num(s) {
        return Some(Value::Num(n));
    }
    // Split on the '-' that separates two valid numbers ("0x10-0x20" safe).
    let (a, b) = s.split_once('-')?;
    let (lo, hi) = (parse_num(a)?, parse_num(b)?);
    Some(if lo <= hi {
        Value::NumRange(lo, hi)
    } else {
        Value::NumRange(hi, lo)
    })
}

fn parse_value(field: Field, s: &str) -> Result<Value, ParseError> {
    match field {
        Field::MacAny | Field::MacSrc | Field::MacDst => parse_mac_pattern(s)
            .ok_or_else(|| ParseError(format!("'{s}' is not a MAC address or MAC pattern"))),
        Field::IpAny | Field::IpSrc | Field::IpDst => parse_ip_pattern(s)
            .ok_or_else(|| ParseError(format!("'{s}' is not an IP address, wildcard, or CIDR"))),
        Field::Proto => parse_proto(s),
        Field::PortAny | Field::Sport | Field::Dport | Field::Ethertype | Field::Vlan
        | Field::Len => parse_num_or_range(s)
            .ok_or_else(|| ParseError(format!("'{s}' is not a number or range (lo-hi)"))),
    }
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    match parse_mac_pattern(s)? {
        Value::Mac(m) => Some(m),
        _ => None,
    }
}

/// `aa:bb:cc:dd:ee:ff` exact; `*` bytes wildcard; a trailing `*` with fewer
/// than 6 parts is a prefix (`aa:bb:*` == `aa:bb:*:*:*:*`).
fn parse_mac_pattern(s: &str) -> Option<Value> {
    let mut pat = [0u8; 6];
    let mut mask = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() > 6 || parts.is_empty() {
        return None;
    }
    if parts.len() < 6 && parts.last() != Some(&"*") {
        return None; // short forms only via trailing *
    }
    for (i, part) in parts.iter().enumerate() {
        if *part == "*" {
            continue; // mask stays 0
        }
        if part.len() != 2 {
            return None;
        }
        pat[i] = u8::from_str_radix(part, 16).ok()?;
        mask[i] = 0xff;
    }
    if mask == [0xff; 6] {
        Some(Value::Mac(pat))
    } else {
        Some(Value::MacMask { pat, mask })
    }
}

/// Exact v4/v6, v4 wildcard octets (`10.10.*.180`, trailing-`*` prefix
/// `10.10.*`), and v4/v6 CIDR (`10.0.0.0/8`, `fe80::/10`).
fn parse_ip_pattern(s: &str) -> Option<Value> {
    if let Some((base, plen)) = s.split_once('/') {
        let plen: u32 = plen.parse().ok()?;
        if let Ok(v4) = base.parse::<std::net::Ipv4Addr>() {
            if plen > 32 {
                return None;
            }
            let m = if plen == 0 { 0u32 } else { u32::MAX << (32 - plen) };
            let mask = m.to_be_bytes();
            let mut pat = v4.octets();
            for i in 0..4 {
                pat[i] &= mask[i];
            }
            return Some(if plen == 32 {
                Value::Ip4(pat)
            } else {
                Value::Ip4Mask { pat, mask }
            });
        }
        if let Ok(v6) = base.parse::<std::net::Ipv6Addr>() {
            if plen > 128 {
                return None;
            }
            let mut mask = [0u8; 16];
            for (i, m) in mask.iter_mut().enumerate() {
                let bits = plen.saturating_sub(i as u32 * 8).min(8);
                *m = if bits == 0 { 0 } else { (!0u8) << (8 - bits) };
            }
            let mut pat = v6.octets();
            for i in 0..16 {
                pat[i] &= mask[i];
            }
            return Some(if plen == 128 {
                Value::Ip6(pat)
            } else {
                Value::Ip6Mask { pat, mask }
            });
        }
        return None;
    }
    if s.contains('*') {
        // v4 wildcard octets; fewer than 4 parts allowed with trailing '*'.
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() > 4 || parts.is_empty() || (parts.len() < 4 && parts.last() != Some(&"*")) {
            return None;
        }
        let mut pat = [0u8; 4];
        let mut mask = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if *part == "*" {
                continue;
            }
            pat[i] = part.parse().ok()?;
            mask[i] = 0xff;
        }
        return Some(Value::Ip4Mask { pat, mask });
    }
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        return Some(Value::Ip4(v4.octets()));
    }
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        return Some(Value::Ip6(v6.octets()));
    }
    None
}

fn parse_proto(s: &str) -> Result<Value, ParseError> {
    // Aliases first, then the full IANA protocol table, then ethertype
    // names, then a raw number.
    let alias = match s {
        "icmp6" => Some(Value::ProtoIp(58)),
        "ip4" => Some(Value::ProtoEther(0x0800)),
        "ip6" => Some(Value::ProtoEther(0x86dd)),
        // ipv4/ipv6 as *protocols* mean the ethertype (any v4/v6 packet),
        // not IANA's ip-in-ip tunneling protocol numbers 4/41.
        "ipv4" => Some(Value::ProtoEther(0x0800)),
        "ipv6" => Some(Value::ProtoEther(0x86dd)),
        _ => None,
    };
    if let Some(v) = alias {
        return Ok(v);
    }
    if let Some(n) = crate::services::ip_proto_by_name(s) {
        return Ok(Value::ProtoIp(n));
    }
    if let Some(t) = crate::services::ethertype_by_name(s) {
        return Ok(Value::ProtoEther(t));
    }
    match parse_num(s) {
        Some(n) if n <= 255 => Ok(Value::ProtoIp(n as u8)),
        _ => Err(ParseError(format!("unknown protocol '{s}'"))),
    }
}

// ---------------------------------------------------------------- evaluation

fn mac_masked_eq(addr: &[u8; 6], pat: &[u8; 6], mask: &[u8; 6]) -> bool {
    (0..6).all(|i| addr[i] & mask[i] == pat[i])
}

impl Expr {
    /// Exact per-packet predicate.
    pub fn matches(&self, meta: &PacketMeta, rec: &PacketRecord) -> bool {
        match self {
            Expr::And(a, b) => a.matches(meta, rec) && b.matches(meta, rec),
            Expr::Or(a, b) => a.matches(meta, rec) || b.matches(meta, rec),
            Expr::Not(e) => !e.matches(meta, rec),
            Expr::In(f, vals) => vals.iter().any(|v| cmp_matches(*f, CmpOp::Eq, *v, meta, rec)),
            Expr::Cmp(f, op, v) => cmp_matches(*f, *op, *v, meta, rec),
        }
    }

    /// Conservative row-group test: false means the group cannot contain a
    /// matching packet; true means it might.
    pub fn may_match_group(&self, g: &RowGroup, dict: &MacDict) -> bool {
        match self {
            Expr::And(a, b) => a.may_match_group(g, dict) && b.may_match_group(g, dict),
            Expr::Or(a, b) => a.may_match_group(g, dict) || b.may_match_group(g, dict),
            // A negation can be satisfied by nearly any packet; never prune.
            Expr::Not(_) => true,
            Expr::In(f, vals) => vals
                .iter()
                .any(|v| cmp_may_match_group(*f, CmpOp::Eq, *v, g, dict)),
            Expr::Cmp(f, op, v) => cmp_may_match_group(*f, *op, *v, g, dict),
        }
    }
}

fn cmp_matches(field: Field, op: CmpOp, v: Value, meta: &PacketMeta, rec: &PacketRecord) -> bool {
    let eq = |b: bool| match op {
        CmpOp::Eq => b,
        CmpOp::Ne => !b,
        _ => false,
    };
    match (field, v) {
        (Field::MacAny, Value::Mac(m)) => {
            eq(meta.has_eth && (meta.mac_src == m || meta.mac_dst == m))
        }
        (Field::MacSrc, Value::Mac(m)) => eq(meta.has_eth && meta.mac_src == m),
        (Field::MacDst, Value::Mac(m)) => eq(meta.has_eth && meta.mac_dst == m),
        (Field::MacAny, Value::MacMask { pat, mask }) => eq(meta.has_eth
            && (mac_masked_eq(&meta.mac_src, &pat, &mask)
                || mac_masked_eq(&meta.mac_dst, &pat, &mask))),
        (Field::MacSrc, Value::MacMask { pat, mask }) => {
            eq(meta.has_eth && mac_masked_eq(&meta.mac_src, &pat, &mask))
        }
        (Field::MacDst, Value::MacMask { pat, mask }) => {
            eq(meta.has_eth && mac_masked_eq(&meta.mac_dst, &pat, &mask))
        }
        (Field::IpAny, val) => eq(ip_matches(&meta.net, val, true, true)),
        (Field::IpSrc, val) => eq(ip_matches(&meta.net, val, true, false)),
        (Field::IpDst, val) => eq(ip_matches(&meta.net, val, false, true)),
        (Field::Proto, Value::ProtoIp(p)) => eq(meta.ip_proto == Some(p)),
        (Field::Proto, Value::ProtoEther(t)) => eq(meta.ethertype == t),
        (Field::PortAny, Value::Num(n)) => {
            let n = n as u16;
            eq(meta.sport == Some(n) || meta.dport == Some(n))
        }
        (Field::PortAny, Value::NumRange(lo, hi)) => {
            let inr = |p: Option<u16>| p.map(|p| (p as u64) >= lo && (p as u64) <= hi) == Some(true);
            eq(inr(meta.sport) || inr(meta.dport))
        }
        (Field::Sport, Value::Num(n)) => num_cmp(op, meta.sport.map(u64::from), n),
        (Field::Dport, Value::Num(n)) => num_cmp(op, meta.dport.map(u64::from), n),
        (Field::Sport, Value::NumRange(lo, hi)) => {
            eq(meta.sport.map(|p| (p as u64) >= lo && (p as u64) <= hi) == Some(true))
        }
        (Field::Dport, Value::NumRange(lo, hi)) => {
            eq(meta.dport.map(|p| (p as u64) >= lo && (p as u64) <= hi) == Some(true))
        }
        (Field::Ethertype, Value::Num(n)) => num_cmp(
            op,
            (meta.ethertype != 0).then_some(meta.ethertype as u64),
            n,
        ),
        (Field::Ethertype, Value::NumRange(lo, hi)) => {
            eq(meta.ethertype != 0 && (meta.ethertype as u64) >= lo && (meta.ethertype as u64) <= hi)
        }
        (Field::Vlan, Value::Num(n)) => num_cmp(op, meta.vlan.map(u64::from), n),
        (Field::Vlan, Value::NumRange(lo, hi)) => {
            eq(meta.vlan.map(|v| (v as u64) >= lo && (v as u64) <= hi) == Some(true))
        }
        (Field::Len, Value::Num(n)) => num_cmp(op, Some(rec.origlen as u64), n),
        (Field::Len, Value::NumRange(lo, hi)) => {
            eq((rec.origlen as u64) >= lo && (rec.origlen as u64) <= hi)
        }
        _ => false,
    }
}

/// Compare an optional field against a literal; missing fields never match.
fn num_cmp(op: CmpOp, actual: Option<u64>, lit: u64) -> bool {
    match actual {
        None => false,
        Some(a) => match op {
            CmpOp::Eq => a == lit,
            CmpOp::Ne => a != lit,
            CmpOp::Lt => a < lit,
            CmpOp::Gt => a > lit,
            CmpOp::Le => a <= lit,
            CmpOp::Ge => a >= lit,
        },
    }
}

fn ip_matches(net: &NetAddrs, v: Value, want_src: bool, want_dst: bool) -> bool {
    let m4 = |a: &[u8; 4], pat: &[u8; 4], mask: &[u8; 4]| (0..4).all(|i| a[i] & mask[i] == pat[i]);
    let m6 =
        |a: &[u8; 16], pat: &[u8; 16], mask: &[u8; 16]| (0..16).all(|i| a[i] & mask[i] == pat[i]);
    match (net, v) {
        (NetAddrs::V4 { src, dst }, Value::Ip4(a)) => {
            (want_src && *src == a) || (want_dst && *dst == a)
        }
        (NetAddrs::V4 { src, dst }, Value::Ip4Mask { pat, mask }) => {
            (want_src && m4(src, &pat, &mask)) || (want_dst && m4(dst, &pat, &mask))
        }
        (NetAddrs::V6 { src, dst }, Value::Ip6(a)) => {
            (want_src && *src == a) || (want_dst && *dst == a)
        }
        (NetAddrs::V6 { src, dst }, Value::Ip6Mask { pat, mask }) => {
            (want_src && m6(src, &pat, &mask)) || (want_dst && m6(dst, &pat, &mask))
        }
        _ => false,
    }
}

fn cmp_may_match_group(field: Field, op: CmpOp, v: Value, g: &RowGroup, dict: &MacDict) -> bool {
    if !matches!(op, CmpOp::Eq) {
        return true; // only equality prunes
    }
    match (field, v) {
        (Field::MacAny | Field::MacSrc | Field::MacDst, Value::Mac(m)) => match dict.lookup(&m) {
            Some(id) => g.macs.may_contain(id),
            None => false, // MAC never appears anywhere in the capture
        },
        // Wildcard MAC: check the group's (small) exact MAC set against the mask.
        (Field::MacAny | Field::MacSrc | Field::MacDst, Value::MacMask { pat, mask }) => {
            if g.macs.is_overflowed() {
                return true;
            }
            g.macs.iter().any(|id| mac_masked_eq(&dict.get(id), &pat, &mask))
        }
        (Field::IpAny | Field::IpSrc | Field::IpDst, Value::Ip4(a)) => g.ip_bloom.may_contain(&a),
        (Field::IpAny | Field::IpSrc | Field::IpDst, Value::Ip6(a)) => g.ip_bloom.may_contain(&a),
        (Field::Proto, Value::ProtoIp(p)) => g.ipprotos.contains(p),
        (Field::Proto, Value::ProtoEther(t)) => g.ethertypes.may_contain(t as u32),
        (Field::Ethertype, Value::Num(n)) => g.ethertypes.may_contain(n as u32),
        (Field::PortAny | Field::Sport | Field::Dport, Value::Num(n)) => {
            g.port_bloom.may_contain(&(n as u16))
        }
        // Small port ranges: OR the bloom point checks; wide ranges don't prune.
        (Field::PortAny | Field::Sport | Field::Dport, Value::NumRange(lo, hi)) => {
            if hi - lo > 64 || hi > u16::MAX as u64 {
                true
            } else {
                (lo..=hi).any(|p| g.port_bloom.may_contain(&(p as u16)))
            }
        }
        _ => true, // masks over blooms, vlan/len ranges: no pruning
    }
}

// ---------------------------------------------------------------- execution

/// Result of a pruned query run.
pub struct QueryRun {
    pub matched: u64,
    pub groups_total: usize,
    pub groups_scanned: usize,
    pub packets_scanned: u64,
}

/// Run `expr` over the capture using tier-0 pruning, reading from the column
/// sidecar when the index has one, otherwise rescanning the capture regions.
/// Calls `on_match(packet_no, rec, meta)` for each hit (return false to stop).
/// Raw bytes for a hit are available via `file.bytes(rec)`.
pub fn run_query(
    file: &PcapFile,
    index: &CaptureIndex,
    expr: &Expr,
    mut on_match: impl FnMut(&PacketRecord, &PacketMeta) -> bool,
) -> Result<QueryRun, FormatError> {
    let mut run = QueryRun {
        matched: 0,
        groups_total: index.groups.len(),
        groups_scanned: 0,
        packets_scanned: 0,
    };
    if index.sidecar.is_some() {
        // Column path: decompress surviving groups, no pcap access at all.
        for gi in 0..index.groups.len() {
            if !expr.may_match_group(&index.groups[gi], &index.dict) {
                continue;
            }
            run.groups_scanned += 1;
            let cols = match index.group_columns(gi) {
                Some(c) => c,
                None => continue,
            };
            for row in 0..cols.len() {
                run.packets_scanned += 1;
                let (rec, meta) = cols.row(row, &index.dict, &index.ip_dict);
                if expr.matches(&meta, &rec) {
                    run.matched += 1;
                    if !on_match(&rec, &meta) {
                        return Ok(run);
                    }
                }
            }
        }
        return Ok(run);
    }
    // Fallback: rescan surviving regions of the capture.
    let mut stop = false;
    let mut gi = 0;
    while gi < index.groups.len() && !stop {
        if !expr.may_match_group(&index.groups[gi], &index.dict) {
            gi += 1;
            continue;
        }
        // Coalesce a run of consecutive surviving groups into one rescan.
        let mut last = gi;
        let mut budget: u64 = index.groups[gi].pkt_count as u64;
        while last + 1 < index.groups.len()
            && expr.may_match_group(&index.groups[last + 1], &index.dict)
        {
            last += 1;
            budget += index.groups[last].pkt_count as u64;
        }
        run.groups_scanned += last - gi + 1;
        let start = index.groups[gi].start_offset;
        let snap = index.snapshot_for(start);
        let mut remaining = budget;
        file.for_each_packet_from(start, snap, |rec, data| {
            let meta = crate::dissect::dissect(rec.linktype, data);
            run.packets_scanned += 1;
            if expr.matches(&meta, &rec) {
                run.matched += 1;
                if !on_match(&rec, &meta) {
                    stop = true;
                    return false;
                }
            }
            remaining -= 1;
            remaining > 0
        })?;
        gi = last + 1;
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        assert!(parse("mac == aa:bb:cc:dd:ee:ff && proto in {tcp, udp}").is_ok());
        assert!(parse("(ip == 10.0.0.1 || port == 53) && !(proto == arp)").is_ok());
        assert!(parse("len > 1000").is_ok());
        assert!(parse("proto == 47").is_ok());
        assert!(parse("bogus == 1").is_err());
        assert!(parse("mac == nonsense").is_err());
        assert!(parse("port > tcp").is_err());
    }

    #[test]
    fn parse_ranges_and_wildcards() {
        assert!(matches!(
            parse_num_or_range("5900-5910"),
            Some(Value::NumRange(5900, 5910))
        ));
        assert!(matches!(
            parse_num_or_range("5910-5900"),
            Some(Value::NumRange(5900, 5910))
        ));
        assert!(matches!(
            parse_ip_pattern("10.10.*.180"),
            Some(Value::Ip4Mask {
                pat: [10, 10, 0, 180],
                mask: [255, 255, 0, 255]
            })
        ));
        assert!(matches!(
            parse_ip_pattern("10.10.*"),
            Some(Value::Ip4Mask {
                pat: [10, 10, 0, 0],
                mask: [255, 255, 0, 0]
            })
        ));
        assert!(matches!(
            parse_ip_pattern("192.168.1.0/24"),
            Some(Value::Ip4Mask {
                pat: [192, 168, 1, 0],
                mask: [255, 255, 255, 0]
            })
        ));
        // CIDR base gets masked: 10.0.0.99/8 == 10.0.0.0/8
        assert!(matches!(
            parse_ip_pattern("10.0.0.99/8"),
            Some(Value::Ip4Mask { pat: [10, 0, 0, 0], .. })
        ));
        assert!(matches!(
            parse_mac_pattern("aa:bb:*:*:*:01"),
            Some(Value::MacMask { .. })
        ));
        assert!(matches!(parse_mac_pattern("aa:bb:*"), Some(Value::MacMask { .. })));
        assert!(parse_mac_pattern("aa:bb").is_none()); // short without *
        assert!(parse("port == 5900-5910 && ip == 10.10.*.180").is_ok());
        assert!(parse("ip in {10.0.0.0/8, 192.168.1.0/24}").is_ok());
        assert!(parse("port in {80, 443, 8000-8100}").is_ok());
        assert!(parse("ip == fe80::/10").is_ok());
        assert!(parse("port < 80-443").is_err()); // ranges only with == / != / in
    }

    #[test]
    fn proto_names() {
        assert_eq!(parse_proto("tcp").unwrap(), Value::ProtoIp(6));
        assert_eq!(parse_proto("arp").unwrap(), Value::ProtoEther(0x0806));
        assert_eq!(parse_proto("255").unwrap(), Value::ProtoIp(255));
    }
}

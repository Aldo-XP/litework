//! Context-aware filter completion for the TUI filter bar: fields → operators
//! → values, with value suggestions drawn from the capture itself (its MACs,
//! IPs, and busiest ports).

use super::App;

pub struct Suggestion {
    /// Text that replaces the partial token when accepted.
    pub insert: String,
    /// Extra explanation shown dimmed to the right.
    pub desc: String,
}

const FIELDS: &[(&str, &str)] = &[
    ("mac", "MAC src or dst — aa:bb:cc:dd:ee:ff, wildcard aa:bb:*"),
    ("mac_src", "source MAC"),
    ("mac_dst", "destination MAC"),
    ("ip", "IP src or dst — 10.0.0.1, 10.10.*.180, 10.0.0.0/8"),
    ("ip_src", "source IP"),
    ("ip_dst", "destination IP"),
    ("proto", "protocol — tcp, udp, icmp, arp, ... or number"),
    ("port", "TCP/UDP src or dst port — 443 or range 5900-5910"),
    ("sport", "source port"),
    ("dport", "destination port"),
    ("ethertype", "ethertype number, e.g. 0x0806"),
    ("vlan", "VLAN id"),
    ("len", "packet length (bytes)"),
    ("data", "raw packet bytes — data contains \"text\" or data contains aa:bb:cc"),
];

const OPERATORS: &[(&str, &str)] = &[
    ("==", "equals (also ranges/wildcards)"),
    ("!=", "not equals"),
    ("in", "in a set: in {a, b, c}"),
    (">", "greater than (numbers)"),
    ("<", "less than (numbers)"),
    (">=", "at least"),
    ("<=", "at most"),
    ("contains", "search raw bytes (data field only): \"text\" or aa:bb:cc"),
];

const PROTOS: &[&str] = &[
    "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp", "ospf", "sctp", "arp", "rarp", "lldp",
    "ipv4", "ipv6",
];

/// Where the caret is in the grammar.
enum Ctx {
    Field,
    Operator,
    Value(String), // field name
}

/// Split the buffer into (everything before the trailing partial token,
/// the partial itself).
pub fn split_partial(buf: &str) -> (&str, &str) {
    let start = buf
        .rfind(|c: char| !(c.is_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '*' | '/')))
        .map(|i| i + 1)
        .unwrap_or(0);
    (&buf[..start], &buf[start..])
}

fn context(before: &str) -> Ctx {
    // Tokenize what's already typed (idents + operator glyphs).
    let mut toks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in before.chars() {
        if c.is_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '*' | '/') {
            cur.push(c);
        } else {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
            if !c.is_whitespace() {
                match toks.last_mut() {
                    // glue two-char operators back together
                    Some(last)
                        if matches!(last.as_str(), "=" | "!" | "<" | ">" | "&" | "|")
                            && matches!(c, '=' | '&' | '|') =>
                    {
                        last.push(c)
                    }
                    _ => toks.push(c.to_string()),
                }
            }
        }
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    let field_of = |toks: &[String]| -> Option<String> {
        toks.iter()
            .rev()
            .find(|t| FIELDS.iter().any(|(f, _)| f == &t.as_str()))
            .cloned()
    };
    match toks.last().map(|s| s.as_str()) {
        Some("==" | "!=" | "<" | ">" | "<=" | ">=" | "in" | "contains" | "{" | ",") => {
            match field_of(&toks) {
                Some(f) => Ctx::Value(f),
                None => Ctx::Field,
            }
        }
        Some(t) if FIELDS.iter().any(|(f, _)| f == &t) => Ctx::Operator,
        _ => Ctx::Field,
    }
}

/// Suggestions for the current buffer; empty when nothing helpful.
pub fn suggestions(app: &mut App, buf: &str) -> Vec<Suggestion> {
    let (before, partial) = split_partial(buf);
    let p = partial.to_ascii_lowercase();
    let mut out = Vec::new();
    match context(before) {
        Ctx::Field => {
            for (f, d) in FIELDS {
                if f.starts_with(&p) {
                    out.push(Suggestion {
                        insert: f.to_string(),
                        desc: d.to_string(),
                    });
                }
            }
        }
        Ctx::Operator => {
            for (o, d) in OPERATORS {
                if p.is_empty() || o.starts_with(&p) {
                    out.push(Suggestion {
                        insert: o.to_string(),
                        desc: d.to_string(),
                    });
                }
            }
        }
        Ctx::Value(field) => value_suggestions(app, &field, &p, &mut out),
    }
    out.truncate(8);
    out
}

fn value_suggestions(app: &mut App, field: &str, p: &str, out: &mut Vec<Suggestion>) {
    match field {
        "proto" => {
            for name in PROTOS {
                if name.starts_with(p) {
                    out.push(Suggestion {
                        insert: name.to_string(),
                        desc: String::new(),
                    });
                }
            }
        }
        "mac" | "mac_src" | "mac_dst" => {
            // MACs actually present, busiest first.
            for (id, m) in app.index.stats.top_macs() {
                let s = litework_core::types::fmt_mac(&app.index.dict.get(id));
                if s.starts_with(p) {
                    out.push(Suggestion {
                        insert: s,
                        desc: format!("{} pkts", m.pkts),
                    });
                    if out.len() >= 8 {
                        break;
                    }
                }
            }
        }
        "ip" | "ip_src" | "ip_dst" => {
            for (ip, pkts) in top_ips(app) {
                if ip.starts_with(p) {
                    out.push(Suggestion {
                        insert: ip.clone(),
                        desc: format!("{pkts} pkts"),
                    });
                    if out.len() >= 8 {
                        break;
                    }
                }
            }
        }
        "port" | "sport" | "dport" => {
            for (port, pkts) in app.index.stats.top_ports(50) {
                let s = port.to_string();
                if s.starts_with(p) {
                    let hint = super::packets::service_hint(port);
                    out.push(Suggestion {
                        insert: s,
                        desc: if hint.is_empty() {
                            format!("{pkts} pkts")
                        } else {
                            format!("{hint} — {pkts} pkts")
                        },
                    });
                    if out.len() >= 8 {
                        break;
                    }
                }
            }
        }
        _ => {}
    }
}

/// IPs seen in the capture, by conversation traffic, cached after first use.
fn top_ips(app: &mut App) -> &[(String, u64)] {
    if app.tables.ips.is_none() {
        let mut per_ip: ahash::AHashMap<u32, u64> = ahash::AHashMap::new();
        for ((a, b), c) in &app.index.stats.convs {
            *per_ip.entry(*a).or_default() += c.pkts;
            *per_ip.entry(*b).or_default() += c.pkts;
        }
        let mut v: Vec<(u32, u64)> = per_ip.into_iter().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(2000);
        app.tables.ips = Some(
            v.into_iter()
                .map(|(id, pkts)| (app.index.ip_dict.fmt(id), pkts))
                .collect(),
        );
    }
    app.tables.ips.as_deref().unwrap()
}

/// Accept a suggestion: replace the trailing partial token.
pub fn accept(buf: &str, s: &Suggestion) -> String {
    let (before, _) = split_partial(buf);
    let mut out = String::with_capacity(before.len() + s.insert.len() + 1);
    out.push_str(before);
    out.push_str(&s.insert);
    out.push(' ');
    out
}

/// The `?` cheat-sheet overlay content.
pub fn help_lines() -> Vec<(&'static str, &'static str)> {
    vec![
        ("FIELDS", ""),
        ("  mac  mac_src  mac_dst", "aa:bb:cc:dd:ee:ff · wildcard aa:bb:*:*:*:01 · prefix aa:bb:*"),
        ("  ip  ip_src  ip_dst", "10.0.0.1 · wildcard 10.10.*.180 · prefix 10.10.* · CIDR 10.0.0.0/8"),
        ("  port  sport  dport", "443 · range 5900-5910"),
        ("  proto", "tcp udp icmp arp lldp goose ... any IANA protocol keyword, or a number"),
        ("  ethertype  vlan  len", "numbers (0x hex ok) · ranges lo-hi"),
        ("  data", "raw frame bytes — Ctrl+F-style search"),
        ("", ""),
        ("OPERATORS", ""),
        ("  ==  !=", "equals / not equals (values, ranges, wildcards)"),
        ("  <  >  <=  >=", "numeric comparison"),
        ("  in {a, b, c}", "any of — sets can mix values and ranges"),
        ("  contains", "data contains \"text\" (case-insensitive) or data contains aa:bb:cc (exact hex)"),
        ("  &&  ||  !  ( )", "and, or, not, grouping"),
        ("", ""),
        ("EXAMPLES", ""),
        ("  ip == 10.10.*.180 && port == 5900-5910", ""),
        ("  mac == aa:bb:* && proto in {tcp, udp}", ""),
        ("  ip_src == 192.168.1.0/24 && !(proto == arp)", ""),
        ("  data contains \"password\"", ""),
        ("  proto == tcp && data contains aa:bb:cc:dd", ""),
        ("", ""),
        ("KEYS", ""),
        ("  tab / ↓↑", "accept / choose completion   ·   enter: apply   esc: cancel"),
    ]
}

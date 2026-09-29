//! Scrollable aggregate tabs: MACS (device ⇄ protocol correlation), PORTS,
//! and FLOWS (IP⇄IP conversations). When a packet filter is active, these
//! tabs aggregate only the matching traffic; Enter pivots into PACKETS,
//! composing with the active filter.

use super::{App, Tab};
use ahash::AHashMap;
use crossterm::event::KeyCode;
use litework_core::types::{fmt_bytes, fmt_mac, fmt_ts, NetAddrs, PacketMeta, PacketRecord, ProtoKey};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Row, Table};
use std::collections::BTreeSet;

/// Cursor + viewport for one scrollable table.
#[derive(Default, Clone, Copy)]
pub struct Scroll {
    pub cursor: usize,
    pub top: usize,
}

impl Scroll {
    fn clamp(&mut self, len: usize, page: usize) {
        if len == 0 {
            *self = Scroll::default();
            return;
        }
        self.cursor = self.cursor.min(len - 1);
        if self.cursor < self.top {
            self.top = self.cursor;
        }
        if self.cursor >= self.top + page {
            self.top = self.cursor + 1 - page;
        }
    }
}

// ---------------------------------------------------------------- aggregates

#[derive(Default, Clone)]
pub struct Agg {
    pub pkts: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub protos: BTreeSet<ProtoKey>,
    pub ports: BTreeSet<u16>,
}

impl Agg {
    fn add(&mut self, rec: &PacketRecord, proto: ProtoKey, meta: &PacketMeta) {
        if self.pkts == 0 {
            self.first_ts = rec.ts_nanos;
        }
        self.pkts += 1;
        self.bytes += rec.origlen as u64;
        self.last_ts = self.last_ts.max(rec.ts_nanos);
        self.protos.insert(proto);
        if self.ports.len() < 64 {
            if let Some(p) = meta.sport {
                self.ports.insert(p);
            }
            if let Some(p) = meta.dport {
                self.ports.insert(p);
            }
        }
    }
}

type IpKey = (u8, [u8; 16]);

/// Aggregates over only the packets matching the active filter, built during
/// the filter's query pass (so they cover every match, not just the ones the
/// packet list materializes).
#[derive(Default)]
pub struct FilteredStats {
    pub packets: u64,
    pub macs: AHashMap<[u8; 6], Agg>,
    pub mac_src: AHashMap<[u8; 6], u64>,
    pub mac_dst: AHashMap<[u8; 6], u64>,
    /// mac_src → mac_dst pair counts.
    pub mac_pairs: AHashMap<([u8; 6], [u8; 6]), u64>,
    pub ports: AHashMap<u16, u64>,
    /// sport → dport pair counts.
    pub pairs: AHashMap<(u16, u16), u64>,
    pub convs: AHashMap<(IpKey, IpKey), Agg>,
}

const FILTER_CONV_CAP: usize = 100_000;

impl FilteredStats {
    pub fn add(&mut self, rec: &PacketRecord, meta: &PacketMeta) {
        self.packets += 1;
        let proto = ProtoKey::of(meta);
        if meta.has_eth {
            for mac in [meta.mac_src, meta.mac_dst] {
                self.macs.entry(mac).or_default().add(rec, proto, meta);
            }
            *self.mac_src.entry(meta.mac_src).or_default() += 1;
            *self.mac_dst.entry(meta.mac_dst).or_default() += 1;
            *self.mac_pairs.entry((meta.mac_src, meta.mac_dst)).or_default() += 1;
        }
        if let Some(p) = meta.sport {
            *self.ports.entry(p).or_default() += 1;
        }
        if let Some(p) = meta.dport {
            *self.ports.entry(p).or_default() += 1;
        }
        if let (Some(s), Some(d)) = (meta.sport, meta.dport) {
            *self.pairs.entry((s, d)).or_default() += 1;
        }
        let key = match meta.net {
            NetAddrs::V4 { src, dst } => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s[..4].copy_from_slice(&src);
                d[..4].copy_from_slice(&dst);
                Some(((4u8, s), (4u8, d)))
            }
            NetAddrs::V6 { src, dst } => Some(((6u8, src), (6u8, dst))),
            NetAddrs::None => None,
        };
        if let Some((a, b)) = key {
            let k = if a <= b { (a, b) } else { (b, a) };
            if self.convs.contains_key(&k) || self.convs.len() < FILTER_CONV_CAP {
                self.convs.entry(k).or_default().add(rec, proto, meta);
            }
        }
    }
}

fn fmt_ip_key(k: &IpKey) -> String {
    if k.0 == 4 {
        std::net::Ipv4Addr::new(k.1[0], k.1[1], k.1[2], k.1[3]).to_string()
    } else {
        std::net::Ipv6Addr::from(k.1).to_string()
    }
}

// ---------------------------------------------------------------- rows

pub struct MacRow {
    pub mac: [u8; 6],
    pub pkts: u64,
    pub src_pkts: u64,
    pub dst_pkts: u64,
    pub bytes: u64,
    pub protos: String,
    pub last_ts: u64,
}

pub struct PortRow {
    pub port: u16,
    pub pkts: u64,
}

pub struct PairRow {
    pub sport: u16,
    pub dport: u16,
    pub pkts: u64,
}

pub struct MacPairRow {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub pkts: u64,
}

pub struct FlowRow {
    pub a: String,
    pub b: String,
    pub pkts: u64,
    pub bytes: u64,
    pub protos: String,
    pub ports: String,
    pub span_secs: f64,
}

/// Rows for the aggregate tabs, rebuilt when the filter changes.
#[derive(Default)]
pub struct Cache {
    pub stamp: Option<String>, // active filter source when rows were built
    pub built: bool,
    /// New live data arrived since the last build.
    pub dirty: bool,
    pub built_at: Option<std::time::Instant>,
    pub macs: Vec<MacRow>,
    pub mac_pairs: Vec<MacPairRow>,
    pub ports: Vec<PortRow>,
    pub pairs: Vec<PairRow>,
    pub flows: Vec<FlowRow>,
    /// IPs for filter-value completion (global, by conversation traffic).
    pub ips: Option<Vec<(String, u64)>>,
}

/// Directional per-MAC counts + sport→dport pairs for the whole capture,
/// swept once from the column store (or one capture walk without a sidecar).
#[derive(Default)]
struct Directional {
    mac_src: AHashMap<[u8; 6], u64>,
    mac_dst: AHashMap<[u8; 6], u64>,
    mac_pairs: AHashMap<([u8; 6], [u8; 6]), u64>,
    pairs: AHashMap<(u16, u16), u64>,
}

fn sweep_directional(app: &App) -> Directional {
    let mut d = Directional::default();
    if app.index.sidecar.is_some() {
        for gi in 0..app.index.groups.len() {
            if let Some(cols) = app.index.group_columns(gi) {
                for i in 0..cols.len() {
                    let flags = cols.flags[i];
                    if flags & litework_core::columns::F_HAS_ETH != 0 {
                        let ms = app.index.dict.get(cols.mac_src[i]);
                        let md = app.index.dict.get(cols.mac_dst[i]);
                        *d.mac_src.entry(ms).or_default() += 1;
                        *d.mac_dst.entry(md).or_default() += 1;
                        *d.mac_pairs.entry((ms, md)).or_default() += 1;
                    }
                    if flags & litework_core::columns::F_HAS_PORTS != 0 {
                        *d.pairs.entry((cols.sport[i], cols.dport[i])).or_default() += 1;
                    }
                }
            }
        }
    } else {
        let _ = app.file.for_each_packet(|rec, data| {
            let meta = litework_core::dissect::dissect(rec.linktype, data);
            if meta.has_eth {
                *d.mac_src.entry(meta.mac_src).or_default() += 1;
                *d.mac_dst.entry(meta.mac_dst).or_default() += 1;
                *d.mac_pairs.entry((meta.mac_src, meta.mac_dst)).or_default() += 1;
            }
            if let (Some(s), Some(dp)) = (meta.sport, meta.dport) {
                *d.pairs.entry((s, dp)).or_default() += 1;
            }
            true
        });
    }
    d
}

fn protos_str(protos: &BTreeSet<ProtoKey>) -> String {
    let v: Vec<String> = protos.iter().map(|p| p.name()).collect();
    format!("{{{}}}", v.join(","))
}

fn ensure_rows(app: &mut App) {
    let stamp = app.filter.as_ref().map(|f| f.source.clone());
    if app.tables.built && app.tables.stamp == stamp {
        // Live data streams in continuously; refresh at most once a second.
        let due = app.tables.dirty
            && app
                .tables
                .built_at
                .map(|t| t.elapsed().as_secs() >= 1)
                .unwrap_or(true);
        if !due {
            return;
        }
    }
    let (mut macs, mut mac_pairs, mut ports, mut pairs, mut flows) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    // Choose the aggregate source: filter stats, live-session stats, or the
    // (immutable) whole-capture index.
    let fstats: Option<&FilteredStats> = match (&app.filter, &app.live) {
        (Some(f), _) => Some(&f.stats),
        (None, Some(l)) => Some(&l.agg),
        (None, None) => None,
    };
    match fstats {
        Some(s) => {
            for (mac, a) in &s.macs {
                macs.push(MacRow {
                    mac: *mac,
                    pkts: a.pkts,
                    src_pkts: s.mac_src.get(mac).copied().unwrap_or(0),
                    dst_pkts: s.mac_dst.get(mac).copied().unwrap_or(0),
                    bytes: a.bytes,
                    protos: protos_str(&a.protos),
                    last_ts: a.last_ts,
                });
            }
            for (p, c) in &s.ports {
                ports.push(PortRow { port: *p, pkts: *c });
            }
            for ((sp, dp), c) in &s.pairs {
                pairs.push(PairRow { sport: *sp, dport: *dp, pkts: *c });
            }
            for ((ms, md), c) in &s.mac_pairs {
                mac_pairs.push(MacPairRow { src: *ms, dst: *md, pkts: *c });
            }
            for ((ka, kb), a) in &s.convs {
                let mut plist: Vec<String> = a.ports.iter().take(4).map(|p| p.to_string()).collect();
                if a.ports.len() > 4 {
                    plist.push("…".into());
                }
                flows.push(FlowRow {
                    a: fmt_ip_key(ka),
                    b: fmt_ip_key(kb),
                    pkts: a.pkts,
                    bytes: a.bytes,
                    protos: protos_str(&a.protos),
                    ports: plist.join(","),
                    span_secs: a.last_ts.saturating_sub(a.first_ts) as f64 / 1e9,
                });
            }
        }
        None => {
            let dir = sweep_directional(app);
            for (id, m) in app.index.stats.top_macs() {
                let mac = app.index.dict.get(id);
                macs.push(MacRow {
                    mac,
                    pkts: m.pkts,
                    src_pkts: dir.mac_src.get(&mac).copied().unwrap_or(0),
                    dst_pkts: dir.mac_dst.get(&mac).copied().unwrap_or(0),
                    bytes: m.bytes,
                    protos: protos_str(&m.protos),
                    last_ts: m.last_ts,
                });
            }
            for (p, c) in app.index.stats.all_ports() {
                ports.push(PortRow { port: p, pkts: c });
            }
            for ((sp, dp), c) in &dir.pairs {
                pairs.push(PairRow { sport: *sp, dport: *dp, pkts: *c });
            }
            for ((ms, md), c) in &dir.mac_pairs {
                mac_pairs.push(MacPairRow { src: *ms, dst: *md, pkts: *c });
            }
            for (key, c) in app.index.stats.top_convs() {
                let mut plist: Vec<String> =
                    c.ports.iter().take(4).map(|p| p.to_string()).collect();
                if c.ports.is_overflowed() || c.ports.len() > 4 {
                    plist.push("…".into());
                }
                flows.push(FlowRow {
                    a: app.index.ip_dict.fmt(key.0),
                    b: app.index.ip_dict.fmt(key.1),
                    pkts: c.pkts,
                    bytes: c.bytes,
                    protos: protos_str(&c.protos),
                    ports: plist.join(","),
                    span_secs: c.last_ts.saturating_sub(c.first_ts) as f64 / 1e9,
                });
            }
        }
    }
    macs.sort_by_key(|r| std::cmp::Reverse(r.pkts));
    mac_pairs.sort_by_key(|r| std::cmp::Reverse(r.pkts));
    ports.sort_by_key(|r| std::cmp::Reverse(r.pkts));
    pairs.sort_by_key(|r| std::cmp::Reverse(r.pkts));
    flows.sort_by_key(|r| std::cmp::Reverse(r.bytes));
    let ips = app.tables.ips.take(); // keep completion cache (global, unaffected)
    let stamp_changed = app.tables.stamp != stamp || !app.tables.built;
    app.tables = Cache {
        stamp,
        built: true,
        dirty: false,
        built_at: Some(std::time::Instant::now()),
        macs,
        mac_pairs,
        ports,
        pairs,
        flows,
        ips,
    };
    // Keep the cursor across live refreshes; reset only on filter change.
    if stamp_changed {
        app.macs_scroll = Scroll::default();
        app.ports_scroll = Scroll::default();
        app.flows_scroll = Scroll::default();
    }
}

fn len_for(app: &App, tab: Tab) -> usize {
    match tab {
        Tab::Macs => {
            if app.macs_pairs {
                app.tables.mac_pairs.len()
            } else {
                app.tables.macs.len()
            }
        }
        Tab::Ports => {
            if app.ports_pairs {
                app.tables.pairs.len()
            } else {
                app.tables.ports.len()
            }
        }
        Tab::Flows => app.tables.flows.len(),
        _ => 0,
    }
}

pub fn handle_key(app: &mut App, tab: Tab, code: KeyCode) {
    ensure_rows(app);
    let len = len_for(app, tab);
    let sc = match tab {
        Tab::Macs => &mut app.macs_scroll,
        Tab::Ports => &mut app.ports_scroll,
        Tab::Flows => &mut app.flows_scroll,
        _ => return,
    };
    match code {
        KeyCode::Up | KeyCode::Char('k') => sc.cursor = sc.cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => sc.cursor = (sc.cursor + 1).min(len.saturating_sub(1)),
        KeyCode::PageUp => sc.cursor = sc.cursor.saturating_sub(30),
        KeyCode::PageDown => sc.cursor = (sc.cursor + 30).min(len.saturating_sub(1)),
        KeyCode::Char('g') | KeyCode::Home => sc.cursor = 0,
        KeyCode::Char('G') | KeyCode::End => sc.cursor = len.saturating_sub(1),
        KeyCode::Enter => pivot(app, tab),
        KeyCode::Char('v') if tab == Tab::Ports => {
            app.ports_pairs = !app.ports_pairs;
            app.ports_scroll = Scroll::default();
        }
        KeyCode::Char('v') if tab == Tab::Macs => {
            app.macs_pairs = !app.macs_pairs;
            app.macs_scroll = Scroll::default();
        }
        _ => {}
    }
}

/// Jump to PACKETS filtered on the selected row, composing with any active filter.
fn pivot(app: &mut App, tab: Tab) {
    let clause = match tab {
        Tab::Macs => {
            if app.macs_pairs {
                app.tables
                    .mac_pairs
                    .get(app.macs_scroll.cursor)
                    .map(|r| format!("mac_src == {} && mac_dst == {}", fmt_mac(&r.src), fmt_mac(&r.dst)))
            } else {
                app.tables
                    .macs
                    .get(app.macs_scroll.cursor)
                    .map(|r| format!("mac == {}", fmt_mac(&r.mac)))
            }
        }
        Tab::Ports => {
            if app.ports_pairs {
                app.tables
                    .pairs
                    .get(app.ports_scroll.cursor)
                    .map(|r| format!("sport == {} && dport == {}", r.sport, r.dport))
            } else {
                app.tables
                    .ports
                    .get(app.ports_scroll.cursor)
                    .map(|r| format!("port == {}", r.port))
            }
        }
        Tab::Flows => app
            .tables
            .flows
            .get(app.flows_scroll.cursor)
            .map(|r| format!("ip == {} && ip == {}", r.a, r.b)),
        _ => None,
    };
    if let Some(clause) = clause {
        let combined = match &app.filter {
            Some(f) if !f.source.contains(&clause) => format!("({}) && {clause}", f.source),
            _ => clause,
        };
        super::packets::apply_filter(app, &combined);
        app.tab = Tab::Packets;
    }
}

/// Mouse click on visible row `row` (0-based from the first data row):
/// first click selects, click on the already-selected row pivots.
pub fn click_row(app: &mut App, tab: Tab, row: usize) {
    ensure_rows(app);
    let len = len_for(app, tab);
    let sc = match tab {
        Tab::Macs => &mut app.macs_scroll,
        Tab::Ports => &mut app.ports_scroll,
        Tab::Flows => &mut app.flows_scroll,
        _ => return,
    };
    let target = sc.top + row;
    if target >= len {
        return;
    }
    if sc.cursor == target {
        pivot(app, tab); // second click = Enter
    } else {
        sc.cursor = target;
    }
}

pub fn draw(f: &mut Frame, app: &mut App, tab: Tab, area: Rect) {
    ensure_rows(app);
    app.regions.body = area;
    let page = area.height.saturating_sub(3).max(1) as usize;
    let len = len_for(app, tab);
    match tab {
        Tab::Macs => app.macs_scroll.clamp(len, page),
        Tab::Ports => app.ports_scroll.clamp(len, page),
        Tab::Flows => app.flows_scroll.clamp(len, page),
        _ => {}
    }
    match tab {
        Tab::Macs => draw_macs(f, app, area, page),
        Tab::Ports => draw_ports(f, app, area, page),
        Tab::Flows => draw_flows(f, app, area, page),
        _ => {}
    }
}

fn sel_style(selected: bool) -> Style {
    if selected {
        Style::new().bg(Color::DarkGray).bold()
    } else {
        Style::new()
    }
}

fn title(app: &App, what: &str, top: usize, page: usize, len: usize) -> String {
    let mut t = format!(
        " {what} {}–{} of {} (enter: show packets) ",
        if len == 0 { 0 } else { top + 1 },
        (top + page).min(len),
        len
    );
    if let Some(f) = &app.filter {
        t.push_str(&format!("· filtered: {} ", f.source));
    }
    t
}

fn draw_macs(f: &mut Frame, app: &mut App, area: Rect, page: usize) {
    let sc = app.macs_scroll;
    if app.macs_pairs {
        let len = app.tables.mac_pairs.len();
        let total = match &app.filter {
            Some(f) => f.stats.packets.max(1),
            None => app.index.stats.packets.max(1),
        };
        let rows: Vec<Row> = app
            .tables
            .mac_pairs
            .iter()
            .enumerate()
            .skip(sc.top)
            .take(page)
            .map(|(i, r)| {
                let pct = r.pkts as f64 * 100.0 / total as f64;
                Row::new(vec![
                    fmt_mac(&r.src),
                    fmt_mac(&r.dst),
                    r.pkts.to_string(),
                    format!("{pct:.2}%"),
                    "▇".repeat(((pct / 100.0 * 30.0).round() as usize).clamp(1, 30)),
                ])
                .style(sel_style(i == sc.cursor))
            })
            .collect();
        let widths = [
            Constraint::Length(19),
            Constraint::Length(19),
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Min(10),
        ];
        let mut t = title(app, "MAC flows src→dst", sc.top, page, len);
        t.push_str("· v: totals ");
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["mac src", "mac dst", "pkts", "share", ""])
                    .style(Style::new().bold().underlined()),
            )
            .block(Block::new().borders(Borders::ALL).title(t));
        f.render_widget(table, area);
        return;
    }
    let len = app.tables.macs.len();
    let rows: Vec<Row> = app
        .tables
        .macs
        .iter()
        .enumerate()
        .skip(sc.top)
        .take(page)
        .map(|(i, r)| {
            Row::new(vec![
                fmt_mac(&r.mac),
                r.src_pkts.to_string(),
                r.dst_pkts.to_string(),
                r.pkts.to_string(),
                fmt_bytes(r.bytes),
                r.protos.clone(),
                fmt_ts(r.last_ts),
            ])
            .style(sel_style(i == sc.cursor))
        })
        .collect();
    let widths = [
        Constraint::Length(18),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Length(10),
        Constraint::Min(18),
        Constraint::Length(23),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["mac", "as src", "as dst", "total", "bytes", "protocols", "last seen"])
                .style(Style::new().bold().underlined()),
        )
        .block(Block::new().borders(Borders::ALL).title({
            let mut t = title(app, "MAC totals", sc.top, page, len);
            t.push_str("· v: src→dst flows ");
            t
        }));
    f.render_widget(table, area);
}

fn draw_ports(f: &mut Frame, app: &mut App, area: Rect, page: usize) {
    let sc = app.ports_scroll;
    let total = match &app.filter {
        Some(f) => f.stats.packets.max(1),
        None => app.index.stats.packets.max(1),
    };
    if app.ports_pairs {
        let len = app.tables.pairs.len();
        let rows: Vec<Row> = app
            .tables
            .pairs
            .iter()
            .enumerate()
            .skip(sc.top)
            .take(page)
            .map(|(i, r)| {
                let pct = r.pkts as f64 * 100.0 / total as f64;
                let svc = |p: u16| {
                    let h = super::packets::service_hint(p);
                    if h.is_empty() { p.to_string() } else { format!("{p} ({h})") }
                };
                Row::new(vec![
                    svc(r.sport),
                    svc(r.dport),
                    r.pkts.to_string(),
                    format!("{pct:.2}%"),
                    "▇".repeat(((pct / 100.0 * 30.0).round() as usize).clamp(1, 30)),
                ])
                .style(sel_style(i == sc.cursor))
            })
            .collect();
        let widths = [
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Min(10),
        ];
        let mut t = title(app, "port pairs src→dst", sc.top, page, len);
        t.push_str("· v: totals ");
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["sport", "dport", "pkts", "share", ""])
                    .style(Style::new().bold().underlined()),
            )
            .block(Block::new().borders(Borders::ALL).title(t));
        f.render_widget(table, area);
    } else {
        let len = app.tables.ports.len();
        let rows: Vec<Row> = app
            .tables
            .ports
            .iter()
            .enumerate()
            .skip(sc.top)
            .take(page)
            .map(|(i, r)| {
                let pct = r.pkts as f64 * 100.0 / total as f64;
                Row::new(vec![
                    r.port.to_string(),
                    super::packets::service_hint(r.port).to_string(),
                    r.pkts.to_string(),
                    format!("{pct:.2}%"),
                    "▇".repeat(((pct / 100.0 * 40.0).round() as usize).clamp(1, 40)),
                ])
                .style(sel_style(i == sc.cursor))
            })
            .collect();
        let widths = [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Min(10),
        ];
        let mut t = title(app, "port totals", sc.top, page, len);
        t.push_str("· v: src→dst pairs ");
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["port", "service", "pkts", "share", ""])
                    .style(Style::new().bold().underlined()),
            )
            .block(Block::new().borders(Borders::ALL).title(t));
        f.render_widget(table, area);
    }
}

fn draw_flows(f: &mut Frame, app: &mut App, area: Rect, page: usize) {
    let sc = app.flows_scroll;
    let len = app.tables.flows.len();
    let rows: Vec<Row> = app
        .tables
        .flows
        .iter()
        .enumerate()
        .skip(sc.top)
        .take(page)
        .map(|(i, r)| {
            Row::new(vec![
                format!("{} ⇄ {}", r.a, r.b),
                r.pkts.to_string(),
                fmt_bytes(r.bytes),
                r.protos.clone(),
                r.ports.clone(),
                format!("{:.1}s", r.span_secs),
            ])
            .style(sel_style(i == sc.cursor))
        })
        .collect();
    let widths = [
        Constraint::Min(35),
        Constraint::Length(11),
        Constraint::Length(10),
        Constraint::Length(18),
        Constraint::Length(22),
        Constraint::Length(9),
    ];
    let mut t = title(app, "flows", sc.top, page, len);
    if app.filter.is_none() && app.index.stats.convs_overflow > 0 {
        t.push_str(&format!("[+{} pkts in untracked flows] ", app.index.stats.convs_overflow));
    }
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["conversation", "pkts", "bytes", "protocols", "ports", "span"])
                .style(Style::new().bold().underlined()),
        )
        .block(Block::new().borders(Borders::ALL).title(t));
    f.render_widget(table, area);
}

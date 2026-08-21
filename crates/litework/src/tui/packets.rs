//! PACKETS tab: virtual-scrolling packet list with filter bar and a detail
//! pane (dissection summary + hex/ASCII dump of the raw bytes, fetched from
//! the mmap on demand — unknown protocols always fully viewable).

use super::{App, Filter, FILTER_CAP};
use crossterm::event::KeyCode;
use litework_core::dissect::dissect;
use litework_core::query::run_query;
use litework_core::PcapWriter;
use litework_core::types::{fmt_mac, fmt_net_addr, fmt_ts, fmt_ts_short, NetAddrs, PacketMeta, PacketRecord, ProtoKey};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};

/// A fetched, dissected run of consecutive rows (the visible slice + margin).
#[derive(Default)]
pub struct Window {
    pub start_row: u64,
    pub rows: Vec<(PacketRecord, PacketMeta)>,
}

/// How many rows to fetch around the viewport per refill.
const WINDOW: u64 = 1024;

impl Window {
    fn contains(&self, first: u64, last: u64) -> bool {
        first >= self.start_row && last < self.start_row + self.rows.len() as u64
    }

    fn get(&self, row: u64) -> Option<&(PacketRecord, PacketMeta)> {
        self.rows.get(row.checked_sub(self.start_row)? as usize)
    }
}

/// Fill the window so rows [first, last] are materialized.
fn ensure_window(app: &mut App, first: u64, last: u64) {
    if app.window.contains(first, last) {
        return;
    }
    let start = first.saturating_sub(WINDOW / 4);
    let want = (last - start + 1).max(WINDOW);
    let mut rows = Vec::with_capacity(want as usize);
    match &app.filter {
        Some(f) => {
            // Filtered domain: records are already materialized; dissect the slice.
            let s = start as usize;
            let e = ((start + want) as usize).min(f.matches.len());
            for rec in &f.matches[s.min(e)..e] {
                let meta = dissect(rec.linktype, app.file.bytes(rec));
                rows.push((*rec, meta));
            }
        }
        None if app.index.sidecar.is_some() => {
            // Column store: fetch rows directly, no pcap access.
            let mut gi = app
                .index
                .groups
                .partition_point(|g| g.first_pkt <= start)
                .saturating_sub(1);
            let mut row = start;
            while (rows.len() as u64) < want {
                let Some(g) = app.index.groups.get(gi) else { break };
                let Some(cols) = app.index.group_columns(gi) else { break };
                let local = (row - g.first_pkt) as usize;
                if local >= cols.len() {
                    gi += 1;
                    continue;
                }
                for i in local..cols.len() {
                    rows.push(cols.row(i, &app.index.dict, &app.index.ip_dict));
                    row += 1;
                    if (rows.len() as u64) >= want {
                        break;
                    }
                }
                gi += 1;
            }
        }
        None => {
            // Unfiltered: walk from the containing row-group boundary.
            let gi = app
                .index
                .groups
                .partition_point(|g| g.first_pkt <= start)
                .saturating_sub(1);
            if let Some(g) = app.index.groups.get(gi) {
                let mut skip = start - g.first_pkt;
                let snap = app.index.snapshot_for(g.start_offset);
                let _ = app.file.for_each_packet_from(g.start_offset, snap, |rec, data| {
                    if skip > 0 {
                        skip -= 1;
                        return true;
                    }
                    rows.push((rec, dissect(rec.linktype, data)));
                    (rows.len() as u64) < want
                });
            }
        }
    }
    app.window = Window { start_row: start, rows };
}

pub fn apply_filter(app: &mut App, src: &str) {
    let src = src.trim();
    app.filter_error = None;
    app.window = Window::default();
    app.cursor = 0;
    app.view_top = 0;
    if src.is_empty() {
        app.filter = None;
        return;
    }
    match litework_core::parse_filter(src) {
        Err(e) => app.filter_error = Some(e.to_string()),
        Ok(expr) => {
            let mut matches = Vec::new();
            let mut fstats = super::tables::FilteredStats::default();
            let run = run_query(&app.file, &app.index, &expr, |rec, meta| {
                fstats.add(rec, meta);
                if matches.len() < FILTER_CAP {
                    matches.push(*rec);
                }
                true // keep aggregating past the display cap
            });
            match run {
                Ok(r) => {
                    app.filter = Some(Filter {
                        source: src.to_string(),
                        expr,
                        truncated: matches.len() >= FILTER_CAP,
                        matches,
                        groups_scanned: r.groups_scanned,
                        groups_total: r.groups_total,
                        stats: fstats,
                    })
                }
                Err(e) => app.filter_error = Some(e.to_string()),
            }
        }
    }
}

pub fn handle_key(app: &mut App, code: KeyCode) {
    app.status = None;
    // Live follow: scrolling away pauses tailing; jump-to-end resumes it.
    if let Some(live) = &mut app.live {
        match code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp | KeyCode::Char('g')
            | KeyCode::Home | KeyCode::Enter => live.follow = false,
            KeyCode::Char('G') | KeyCode::End => live.follow = true,
            _ => {}
        }
    }
    let total = app.total_rows();
    let last = total.saturating_sub(1);
    match code {
        KeyCode::Char('w') => {
            app.save_input = Some((default_save_name(), false));
        }
        KeyCode::Char('/') => {
            app.filter_input = Some(
                app.filter.as_ref().map(|f| f.source.clone()).unwrap_or_default(),
            )
        }
        KeyCode::Esc => {
            if app.detail {
                app.detail = false;
            } else {
                apply_filter(app, "");
            }
        }
        KeyCode::Enter => {
            app.detail = !app.detail;
            app.detail_scroll = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.cursor = (app.cursor + 1).min(last),
        KeyCode::PageUp => app.cursor = app.cursor.saturating_sub(30),
        KeyCode::PageDown => app.cursor = (app.cursor + 30).min(last),
        KeyCode::Char('g') | KeyCode::Home => app.cursor = 0,
        KeyCode::Char('G') | KeyCode::End => app.cursor = last,
        KeyCode::Char('+') | KeyCode::Char(']') => {
            app.detail_scroll = app.detail_scroll.saturating_add(4)
        }
        KeyCode::Char('-') | KeyCode::Char('[') => {
            app.detail_scroll = app.detail_scroll.saturating_sub(4)
        }
        _ => {}
    }
    if total == 0 {
        app.cursor = 0;
    }
}

pub fn default_save_name() -> String {
    format!(
        "litework-{}.pcap",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )
}

/// Write the current view (filter matches; otherwise the whole capture /
/// live spool) to `name`. Returns true on success.
pub fn save_to(app: &mut App, name: &str) -> bool {
    let path = std::path::PathBuf::from(name);
    // Live with no filter: snapshot the spool file directly.
    if let (None, Some(live)) = (&app.filter, &app.live) {
        let src = live.spool_path.clone();
        let _ = app.file.refresh();
        return match std::fs::copy(&src, &path) {
            Ok(bytes) => {
                app.status = Some(format!(
                    "saved {} pkts ({}) → {}",
                    app.index.stats.packets,
                    litework_core::types::fmt_bytes(bytes),
                    name
                ));
                true
            }
            Err(e) => {
                app.status = Some(format!("save failed: {e}"));
                false
            }
        };
    }
    let result = (|| -> anyhow::Result<(u64, u64, u64)> {
        let mut writer: Option<PcapWriter> = None;
        match &app.filter {
            Some(fl) => {
                for rec in &fl.matches {
                    let data = app.file.bytes(rec);
                    let w = match &mut writer {
                        Some(w) => w,
                        None => {
                            writer = Some(PcapWriter::create(&path, rec.linktype)?);
                            writer.as_mut().unwrap()
                        }
                    };
                    w.write(rec.ts_nanos, rec.origlen, rec.linktype, data)?;
                }
            }
            None => {
                app.file.for_each_packet(|rec, data| {
                    let w = match &mut writer {
                        Some(w) => w,
                        None => {
                            writer = Some(PcapWriter::create(&path, rec.linktype).expect("create"));
                            writer.as_mut().unwrap()
                        }
                    };
                    w.write(rec.ts_nanos, rec.origlen, rec.linktype, data).is_ok()
                })?;
            }
        }
        match writer {
            Some(w) => Ok(w.finish()?),
            None => Ok((0, 0, 0)),
        }
    })();
    match result {
        Ok((pkts, bytes, skipped)) => {
            let mut m = format!(
                "saved {} pkts ({}) → {}",
                pkts,
                litework_core::types::fmt_bytes(bytes),
                name
            );
            if skipped > 0 {
                m.push_str(&format!(" ({skipped} skipped: mixed linktype)"));
            }
            app.status = Some(m);
            true
        }
        Err(e) => {
            app.status = Some(format!("save failed: {e}"));
            false
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let detail_h = if app.detail { area.height / 2 } else { 0 };
    let [bar_area, list_area, detail_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(detail_h),
    ])
    .areas(area);

    draw_filter_bar(f, app, bar_area);
    app.regions.bar = bar_area;
    app.regions.body = list_area;
    app.regions.detail = detail_area;

    // Virtual scroll bookkeeping.
    let total = app.total_rows();
    let page = list_area.height.saturating_sub(2).max(1) as u64; // borders+header
    if app.cursor < app.view_top {
        app.view_top = app.cursor;
    }
    if app.cursor >= app.view_top + page {
        app.view_top = app.cursor + 1 - page;
    }
    let first = app.view_top;
    let last = (first + page).min(total).saturating_sub(1);
    if total > 0 {
        ensure_window(app, first, last.max(first));
    }

    let header = Row::new(vec![
        "#", "time", "mac src", "mac dst", "src → dst", "proto", "ports", "len",
    ])
    .style(Style::new().bold().underlined());
    let mut rows_out = Vec::new();
    if total > 0 {
        for row_no in first..=last {
            let style = if row_no == app.cursor {
                Style::new().bg(Color::DarkGray).bold()
            } else {
                Style::new()
            };
            let cells = match app.window.get(row_no) {
                Some((rec, meta)) => {
                    let (src, dst) = fmt_net_addr(&meta.net);
                    let ports = match (meta.sport, meta.dport) {
                        (Some(s), Some(d)) => format!("{s}→{d}"),
                        _ => "-".into(),
                    };
                    vec![
                        row_no.to_string(),
                        fmt_ts_short(rec.ts_nanos),
                        if meta.has_eth { fmt_mac(&meta.mac_src) } else { "-".into() },
                        if meta.has_eth { fmt_mac(&meta.mac_dst) } else { "-".into() },
                        format!("{src} → {dst}"),
                        ProtoKey::of(meta).name(),
                        ports,
                        rec.origlen.to_string(),
                    ]
                }
                None => vec!["…".into(); 8],
            };
            rows_out.push(Row::new(cells).style(style));
        }
    }
    let widths = [
        Constraint::Length(9),
        Constraint::Length(12),
        Constraint::Length(17),
        Constraint::Length(17),
        Constraint::Min(29),
        Constraint::Length(9),
        Constraint::Length(12),
        Constraint::Length(6),
    ];
    let title = format!(" packets {}–{} of {} ", first.min(total), last + 1, total);
    let table = Table::new(rows_out, widths)
        .header(header)
        .block(Block::new().borders(Borders::ALL).title(title));
    f.render_widget(table, list_area);

    if app.detail && total > 0 {
        draw_detail(f, app, detail_area);
    }

    // Drawn last so the popup layers cleanly over the table.
    if app.filter_input.is_some() {
        draw_suggestions(f, app, bar_area, list_area);
    }
}

/// Completion dropdown under the filter bar (drawn over the packet table).
fn draw_suggestions(f: &mut Frame, app: &mut App, bar: Rect, below: Rect) {
    use ratatui::widgets::Clear;
    let buf = app.filter_input.clone().unwrap_or_default();
    let sugg = super::suggest::suggestions(app, &buf);
    if sugg.is_empty() {
        return;
    }
    app.suggest_sel = app.suggest_sel.min(sugg.len() - 1);
    let width = sugg
        .iter()
        .map(|s| s.insert.len() + s.desc.len() + 5)
        .max()
        .unwrap_or(20)
        .clamp(24, below.width.saturating_sub(4) as usize) as u16;
    let height = (sugg.len() as u16 + 2).min(below.height);
    // Anchor near the caret column.
    let caret = 8 + buf.len() as u16;
    let x = (bar.x + caret.min(bar.width.saturating_sub(width + 1))).max(below.x);
    let area = Rect::new(x, below.y, width, height);
    f.render_widget(Clear, area);
    let mut lines = Vec::new();
    for (i, s) in sugg.iter().enumerate() {
        let style = if i == app.suggest_sel {
            Style::new().bg(Color::DarkGray).bold()
        } else {
            Style::new()
        };
        lines.push(
            Line::from(vec![
                Span::styled(format!(" {:<14}", s.insert), style.fg(Color::Yellow)),
                Span::styled(format!("{} ", s.desc), style.fg(Color::Gray)),
            ])
            .style(style),
        );
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" tab: complete · ?: syntax "),
        ),
        area,
    );
}

fn draw_filter_bar(f: &mut Frame, app: &App, area: Rect) {
    let line = if let Some(msg) = &app.status {
        Line::from(Span::styled(format!("✓ {msg}"), Style::new().fg(Color::Green)))
    } else if let Some(buf) = &app.filter_input {
        Line::from(vec![
            Span::styled("filter> ", Style::new().bold().fg(Color::Yellow)),
            Span::raw(buf.clone()),
            Span::styled("█", Style::new().fg(Color::Yellow)),
        ])
    } else if let Some(err) = &app.filter_error {
        Line::from(Span::styled(format!("✗ {err}"), Style::new().fg(Color::Red)))
    } else if let Some(fl) = &app.filter {
        let mut spans = vec![
            Span::styled("filter: ", Style::new().dim()),
            Span::styled(fl.source.clone(), Style::new().fg(Color::Yellow)),
            Span::styled(
                format!(
                    "   {} matches, scanned {}/{} groups",
                    fl.matches.len(),
                    fl.groups_scanned,
                    fl.groups_total
                ),
                Style::new().dim(),
            ),
        ];
        if fl.truncated {
            spans.push(Span::styled(
                format!("  (capped at {FILTER_CAP})"),
                Style::new().fg(Color::Red),
            ));
        }
        Line::from(spans)
    } else {
        Line::from(Span::styled(
            "no filter — press / to filter (e.g. mac == aa:bb:cc:dd:ee:ff && proto == tcp)",
            Style::new().dim(),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some((rec, meta)) = app.window.get(app.cursor) else {
        return;
    };
    let data = app.file.bytes(rec);
    let [sum_area, hex_area] =
        Layout::horizontal([Constraint::Length(38), Constraint::Min(20)]).areas(area);

    // Dissection summary.
    let mut lines = vec![
        kv("packet", &app.cursor.to_string()),
        kv("time", &fmt_ts(rec.ts_nanos)),
        kv("offset", &format!("0x{:x}", rec.data_offset)),
        kv("caplen/len", &format!("{}/{}", rec.caplen, rec.origlen)),
        kv("linktype", &rec.linktype.to_string()),
    ];
    if meta.has_eth {
        lines.push(kv("eth src", &fmt_mac(&meta.mac_src)));
        lines.push(kv("eth dst", &fmt_mac(&meta.mac_dst)));
        lines.push(kv("ethertype", &format!("0x{:04x}", meta.ethertype)));
    }
    if let Some(v) = meta.vlan {
        lines.push(kv("vlan", &v.to_string()));
    }
    let (src, dst) = fmt_net_addr(&meta.net);
    if !matches!(meta.net, NetAddrs::None) {
        lines.push(kv("ip src", &src));
        lines.push(kv("ip dst", &dst));
    }
    if let Some(p) = meta.ip_proto {
        lines.push(kv("ip proto", &format!("{} ({})", p, ProtoKey::Ip(p).name())));
    }
    if let (Some(s), Some(d)) = (meta.sport, meta.dport) {
        let svc = |p: u16| match litework_core::services::service_name(p) {
            Some(n) => format!("{p} ({n})"),
            None => p.to_string(),
        };
        lines.push(kv("ports", &format!("{} → {}", svc(s), svc(d))));
    }
    if let Some(fl) = meta.tcp_flags {
        lines.push(kv("tcp flags", &tcp_flags_str(fl)));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" dissection ")),
        sum_area,
    );

    // Hex + ASCII dump (scroll with +/-).
    let mut hex_lines = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '·' })
            .collect();
        hex_lines.push(Line::from(vec![
            Span::styled(format!("{:06x}  ", i * 16), Style::new().dim()),
            Span::raw(format!("{:<47}  ", hex.join(" "))),
            Span::styled(ascii, Style::new().fg(Color::Green)),
        ]));
    }
    let n = hex_lines.len();
    f.render_widget(
        Paragraph::new(hex_lines)
            .scroll((app.detail_scroll, 0))
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(format!(" raw bytes ({} B, +/- scroll, {n} lines) ", data.len())),
            ),
        hex_area,
    );
}


fn kv(k: &str, v: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k:<11}"), Style::new().dim()),
        Span::raw(v.to_string()),
    ])
}

fn tcp_flags_str(f: u8) -> String {
    let names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"];
    let set: Vec<&str> = names
        .iter()
        .enumerate()
        .filter(|(i, _)| f >> i & 1 == 1)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() { "none".into() } else { set.join(",") }
}

pub fn service_hint(port: u16) -> &'static str {
    litework_core::services::service_name(port).unwrap_or("")
}

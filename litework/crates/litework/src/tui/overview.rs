//! OVERVIEW tab: traffic histogram, protocol mix, top MACs (with the protocol
//! sets they speak), top ports.

use super::App;
use litework_core::types::{fmt_bytes, fmt_mac, fmt_ts};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let [time_area, spark_area, cols_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(6),
        Constraint::Min(4),
    ])
    .areas(area);

    let s = &app.index.stats;
    let dur = if s.first_ts != u64::MAX {
        format!(
            "{}  →  {}   ({:.1}s)   {} row groups, indexed in {} ms",
            fmt_ts(s.first_ts),
            fmt_ts(s.last_ts),
            (s.last_ts.saturating_sub(s.first_ts)) as f64 / 1e9,
            app.index.groups.len(),
            app.index.build_millis,
        )
    } else {
        "no timestamps".into()
    };
    f.render_widget(Paragraph::new(dur).style(Style::new().dim()), time_area);

    // Histogram, downsampled to the pane width.
    if let Some((a, b)) = s.hist.span() {
        let counts = &s.hist.counts()[a..=b];
        let w = spark_area.width.saturating_sub(2) as usize;
        let ncols = w.max(1);
        let mut cols = vec![0u64; ncols];
        for (i, &c) in counts.iter().enumerate() {
            cols[i * ncols / counts.len()] += c;
        }
        let per_col =
            s.hist.width_nanos() as f64 * counts.len() as f64 / cols.len() as f64 / 1e9;
        let spark = Sparkline::default()
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(format!(" traffic ({per_col:.1}s/col) ")),
            )
            .data(&cols)
            .style(Style::new().fg(Color::Cyan));
        f.render_widget(spark, spark_area);
    }

    let [protos_area, macs_area, ports_area] = Layout::horizontal([
        Constraint::Percentage(32),
        Constraint::Percentage(45),
        Constraint::Percentage(23),
    ])
    .areas(cols_area);

    // Protocol mix.
    let mut lines = Vec::new();
    for (k, pkts, bytes) in s.top_protos().into_iter().take(protos_area.height as usize) {
        let pct = pkts as f64 * 100.0 / s.packets.max(1) as f64;
        let bar = "▇".repeat(((pct / 100.0 * 14.0).round() as usize).max(1));
        lines.push(Line::from(vec![
            Span::styled(format!("{:<11}", k.name()), Style::new().bold()),
            Span::raw(format!("{pct:>5.1}% ")),
            Span::styled(format!("{bar:<15}"), Style::new().fg(Color::Green)),
            Span::styled(fmt_bytes(bytes), Style::new().dim()),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" protocols ")),
        protos_area,
    );

    // Top MACs with protocol sets — the core correlation view.
    let mut lines = Vec::new();
    for (id, m) in s.top_macs().into_iter().take(macs_area.height as usize) {
        let protos: Vec<String> = m.protos.iter().map(|p| p.name()).collect();
        lines.push(Line::from(vec![
            Span::styled(fmt_mac(&app.index.dict.get(id)), Style::new().fg(Color::Yellow)),
            Span::raw(format!(" {:>9} ", m.pkts)),
            Span::styled(format!("{{{}}}", protos.join(",")), Style::new().fg(Color::Magenta)),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(format!(" top MACs ({} seen) ", app.index.dict.len())),
        ),
        macs_area,
    );

    // Top ports.
    let mut lines = Vec::new();
    for (p, c) in s.top_ports(ports_area.height as usize) {
        lines.push(Line::from(vec![
            Span::styled(format!("{p:<6}"), Style::new().bold()),
            Span::raw(format!("{c:>9} ")),
            Span::styled(super::packets::service_hint(p), Style::new().dim()),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" top ports ")),
        ports_area,
    );
}

//! LiteWork interactive TUI: OVERVIEW and PACKETS tabs over the tier-0 index.
//! The packet list is virtual — rows are fetched on demand by walking from the
//! nearest row-group boundary, so scrolling a 100M-packet capture stays flat.

pub mod live;
mod overview;
pub mod packets;
mod suggest;
mod tables;

use anyhow::Result;
use std::time::Instant;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use litework_core::query::Expr;
use litework_core::types::PacketRecord;
use litework_core::{CaptureIndex, PcapFile};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Tabs};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Packets,
    Macs,
    Ports,
    Flows,
}

pub struct Filter {
    pub source: String,
    pub expr: Expr,
    /// Matching records (capped); None while unset.
    pub matches: Vec<PacketRecord>,
    pub truncated: bool,
    pub groups_scanned: usize,
    pub groups_total: usize,
    /// Aggregates over ALL matches (not capped) — feeds MACS/PORTS/FLOWS.
    pub stats: tables::FilteredStats,
}

/// Cap on materialized filter matches; keeps worst-case RAM bounded (~4 MB).
pub const FILTER_CAP: usize = 100_000;

pub struct App {
    pub file: PcapFile,
    pub index: CaptureIndex,
    pub tab: Tab,
    // packets tab
    pub cursor: u64,
    pub view_top: u64,
    pub filter: Option<Filter>,
    pub filter_input: Option<String>,
    pub filter_error: Option<String>,
    pub detail: bool,
    pub detail_scroll: u16,
    pub window: packets::Window,
    /// Transient status line (e.g. after saving an export).
    pub status: Option<String>,
    pub macs_scroll: tables::Scroll,
    pub ports_scroll: tables::Scroll,
    pub flows_scroll: tables::Scroll,
    pub tables: tables::Cache,
    /// Selected row in the filter completion popup.
    pub suggest_sel: usize,
    pub show_help: bool,
    /// PORTS tab mode: sport→dport pairs (true) or single-port totals.
    pub ports_pairs: bool,
    /// MACS tab mode: mac_src→mac_dst flows (true) or per-MAC totals.
    pub macs_pairs: bool,
    /// Live capture session (None when viewing a file).
    pub live: Option<live::Live>,
    /// Save-as prompt buffer; bool = quit after a successful save.
    pub save_input: Option<(String, bool)>,
    /// Quit confirmation for a temp live spool.
    pub quit_confirm: bool,
    /// Screen regions from the last draw, for mouse hit-testing.
    pub regions: Regions,
    quit: bool,
}

/// Where things were drawn last frame.
#[derive(Default, Clone, Copy)]
pub struct Regions {
    pub tabs: Rect,
    /// Filter bar row (packets tab only).
    pub bar: Rect,
    /// Table/list body: first data row is `body.y + 2` (border + header).
    pub body: Rect,
    pub detail: Rect,
}

impl App {
    pub fn new(file: PcapFile, index: CaptureIndex) -> Self {
        App {
            file,
            index,
            tab: Tab::Overview,
            cursor: 0,
            view_top: 0,
            filter: None,
            filter_input: None,
            filter_error: None,
            detail: false,
            detail_scroll: 0,
            window: packets::Window::default(),
            status: None,
            macs_scroll: tables::Scroll::default(),
            ports_scroll: tables::Scroll::default(),
            flows_scroll: tables::Scroll::default(),
            tables: tables::Cache::default(),
            suggest_sel: 0,
            show_help: false,
            ports_pairs: true,
            macs_pairs: false,
            live: None,
            save_input: None,
            quit_confirm: false,
            regions: Regions::default(),
            quit: false,
        }
    }

    /// Rows in the current view domain (all packets, or filter matches).
    pub fn total_rows(&self) -> u64 {
        match &self.filter {
            Some(f) => f.matches.len() as u64,
            None => self.index.stats.packets,
        }
    }
}

pub fn run(file: PcapFile, index: CaptureIndex, initial_filter: Option<String>) -> Result<()> {
    run_with(file, index, initial_filter, None)
}

/// Live-TUI entry: same App over a growing spool file.
pub fn run_live(
    file: PcapFile,
    index: CaptureIndex,
    initial_filter: Option<String>,
    live: live::Live,
) -> Result<()> {
    run_with(file, index, initial_filter, Some(live))
}

fn run_with(
    file: PcapFile,
    index: CaptureIndex,
    initial_filter: Option<String>,
    live: Option<live::Live>,
) -> Result<()> {
    let mut terminal = ratatui::init();
    let _ = crossterm::execute!(std::io::stdout(), EnableMouseCapture);
    let mut app = App::new(file, index);
    app.live = live;
    if app.live.is_some() {
        app.tab = Tab::Packets; // live opens on the tailing packet list
    }
    if let Some(src) = initial_filter {
        packets::apply_filter(&mut app, &src);
        app.tab = Tab::Packets;
    }
    let res = event_loop(&mut terminal, &mut app);
    if let Some(l) = &mut app.live {
        l.shutdown();
        if l.temp {
            l.discard_spool(); // reached only via the discard path or error
        }
    }
    let _ = crossterm::execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    res
}

/// Drain live packets into the index (and the active filter) each tick.
fn drain_live(app: &mut App) {
    let Some(mut live) = app.live.take() else { return };
    let mut ingested = 0u32;
    let mut kernel: Option<(u64, u64)> = None;
    // Bounded per tick so the UI stays responsive under floods.
    while ingested < 50_000 {
        match live.rx.try_recv() {
            Ok(live::Msg::Pkt(rec, data)) => {
                let meta = app.index.live_append(&rec, &data);
                // Keep whole-session aggregates for the MACS/PORTS/FLOWS tabs
                // (avoids rescanning the growing spool on every rebuild).
                live.agg.add(&rec, &meta);
                if let Some(fl) = &mut app.filter {
                    if fl.expr.matches(&meta, &rec) {
                        fl.stats.add(&rec, &meta);
                        if fl.matches.len() < FILTER_CAP {
                            fl.matches.push(rec);
                        } else {
                            fl.truncated = true;
                        }
                    }
                }
                ingested += 1;
            }
            Ok(live::Msg::Stats(r, d)) => kernel = Some((r, d)),
            Err(_) => break,
        }
    }
    if let Some((r, d)) = kernel {
        live.kernel_recv = r;
        live.kernel_drop = d;
    }
    if ingested > 0 {
        let _ = app.file.refresh();
        app.window = packets::Window::default(); // stale rows: refetch
        app.tables.dirty = true; // rebuilt at most once per second
    }
    // pkt/s over a rolling ~1s window
    let dt = live.last_rate_at.elapsed().as_secs_f64();
    if dt >= 1.0 {
        live.rate = (app.index.stats.packets - live.last_rate_pkts) as f64 / dt;
        live.last_rate_pkts = app.index.stats.packets;
        live.last_rate_at = Instant::now();
    }
    // Follow the newest packet unless the user scrolled away.
    if live.follow && app.filter_input.is_none() {
        let total = app.total_rows();
        if total > 0 {
            app.cursor = total - 1;
        }
    }
    app.live = Some(live);
}

fn event_loop(terminal: &mut Terminal<impl Backend>, app: &mut App) -> Result<()> {
    while !app.quit {
        drain_live(app);
        terminal.draw(|f| draw(f, app))?;
        let timeout = if app.live.is_some() {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(250)
        };
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => handle_key(app, k.code, k.modifiers),
                Event::Mouse(m) => handle_mouse(app, m),
                _ => {}
            }
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Save-as prompt swallows everything.
    if let Some((buf, then_quit)) = &mut app.save_input {
        if mods == KeyModifiers::CONTROL {
            if code == KeyCode::Char('u') {
                buf.clear();
            }
            return;
        }
        match code {
            KeyCode::Esc => app.save_input = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Enter => {
                let (name, then_quit) = (buf.clone(), *then_quit);
                app.save_input = None;
                let ok = packets::save_to(app, &name);
                if ok && then_quit {
                    if let Some(l) = &mut app.live {
                        l.discard_spool(); // copy taken; temp spool goes away
                    }
                    app.live = None;
                    app.quit = true;
                }
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return;
    }
    // Quit confirmation for a temp live spool.
    if app.quit_confirm {
        match code {
            KeyCode::Char('s') => {
                app.quit_confirm = false;
                if let Some(l) = &mut app.live {
                    l.shutdown(); // freeze the spool before copying
                }
                app.save_input = Some((packets::default_save_name(), true));
            }
            KeyCode::Char('d') => {
                if let Some(l) = &mut app.live {
                    l.discard_spool();
                }
                app.live = None;
                app.quit = true;
            }
            KeyCode::Esc => app.quit_confirm = false,
            _ => {}
        }
        return;
    }
    // Help overlay swallows everything until dismissed.
    if app.show_help {
        if matches!(code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')) {
            app.show_help = false;
        }
        return;
    }
    // Filter entry mode swallows everything.
    if app.filter_input.is_some() {
        if mods == KeyModifiers::CONTROL {
            if code == KeyCode::Char('u') {
                if let Some(buf) = &mut app.filter_input {
                    buf.clear();
                }
                app.suggest_sel = 0;
            }
            return;
        }
        match code {
            KeyCode::Esc => {
                app.filter_input = None;
                app.filter_error = None;
            }
            KeyCode::Enter => {
                let src = app.filter_input.take().unwrap();
                packets::apply_filter(app, &src);
            }
            KeyCode::Backspace => {
                if let Some(buf) = &mut app.filter_input {
                    buf.pop();
                }
                app.suggest_sel = 0;
            }
            KeyCode::Down => app.suggest_sel = app.suggest_sel.saturating_add(1),
            KeyCode::Up => app.suggest_sel = app.suggest_sel.saturating_sub(1),
            KeyCode::Tab | KeyCode::Right => {
                // Accept the highlighted completion.
                let buf = app.filter_input.clone().unwrap_or_default();
                let sugg = suggest::suggestions(app, &buf);
                if let Some(s) = sugg.get(app.suggest_sel.min(sugg.len().saturating_sub(1))) {
                    app.filter_input = Some(suggest::accept(&buf, s));
                    app.suggest_sel = 0;
                }
            }
            KeyCode::Char('?') => {
                app.show_help = true;
            }
            KeyCode::Char(c) => {
                if let Some(buf) = &mut app.filter_input {
                    buf.push(c);
                }
                app.suggest_sel = 0;
            }
            _ => {}
        }
        return;
    }
    if code == KeyCode::Char('?') {
        app.show_help = true;
        return;
    }
    match (code, mods) {
        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            match &app.live {
                Some(l) if l.temp && app.index.stats.packets > 0 => app.quit_confirm = true,
                _ => app.quit = true,
            }
        }
        (KeyCode::Tab, _) => {
            app.tab = match app.tab {
                Tab::Overview => Tab::Packets,
                Tab::Packets => Tab::Macs,
                Tab::Macs => Tab::Ports,
                Tab::Ports => Tab::Flows,
                Tab::Flows => Tab::Overview,
            }
        }
        (KeyCode::BackTab, _) => {
            app.tab = match app.tab {
                Tab::Overview => Tab::Flows,
                Tab::Packets => Tab::Overview,
                Tab::Macs => Tab::Packets,
                Tab::Ports => Tab::Macs,
                Tab::Flows => Tab::Ports,
            }
        }
        (KeyCode::Char(' '), _) if app.live.is_some() => {
            let live = app.live.as_mut().unwrap();
            if live.running {
                live.shutdown();
                app.status = Some("capture stopped — space resumes".into());
            } else {
                match live.resume() {
                    Ok(()) => app.status = Some("capture resumed".into()),
                    Err(e) => app.status = Some(format!("resume failed: {e}")),
                }
            }
        }
        (KeyCode::Char('1'), _) => app.tab = Tab::Overview,
        (KeyCode::Char('2'), _) => app.tab = Tab::Packets,
        (KeyCode::Char('3'), _) => app.tab = Tab::Macs,
        (KeyCode::Char('4'), _) => app.tab = Tab::Ports,
        (KeyCode::Char('5'), _) => app.tab = Tab::Flows,
        _ => match app.tab {
            Tab::Packets => packets::handle_key(app, code),
            Tab::Macs | Tab::Ports | Tab::Flows => tables::handle_key(app, app.tab, code),
            Tab::Overview => {}
        },
    }
}

fn handle_mouse(app: &mut App, m: MouseEvent) {
    // Modals and text prompts stay keyboard-driven.
    if app.show_help || app.quit_confirm || app.save_input.is_some() || app.filter_input.is_some()
    {
        return;
    }
    let inside = |r: Rect| {
        m.column >= r.x && m.column < r.right() && m.row >= r.y && m.row < r.bottom()
    };
    match m.kind {
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            let up = matches!(m.kind, MouseEventKind::ScrollUp);
            // Wheel over an open detail pane scrolls the hex dump.
            if app.detail && inside(app.regions.detail) {
                app.detail_scroll = if up {
                    app.detail_scroll.saturating_sub(3)
                } else {
                    app.detail_scroll.saturating_add(3)
                };
                return;
            }
            let key = if up { KeyCode::PageUp } else { KeyCode::PageDown };
            // Reuse the keyboard paths (follow-pause etc.) with a small step.
            for _ in 0..1 {
                match app.tab {
                    Tab::Packets => {
                        // 3-row wheel step instead of a full page
                        if up {
                            if let Some(l) = &mut app.live {
                                l.follow = false;
                            }
                            app.cursor = app.cursor.saturating_sub(3);
                        } else {
                            app.cursor = (app.cursor + 3).min(app.total_rows().saturating_sub(1));
                        }
                    }
                    Tab::Macs | Tab::Ports | Tab::Flows => {
                        let _ = key; // tables use their own cursor math
                        tables::handle_key(
                            app,
                            app.tab,
                            if up { KeyCode::Up } else { KeyCode::Down },
                        );
                        // two extra rows for a natural wheel feel
                        tables::handle_key(
                            app,
                            app.tab,
                            if up { KeyCode::Up } else { KeyCode::Down },
                        );
                        tables::handle_key(
                            app,
                            app.tab,
                            if up { KeyCode::Up } else { KeyCode::Down },
                        );
                    }
                    Tab::Overview => {}
                }
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            // Tab strip.
            if inside(app.regions.tabs) {
                if let Some(tab) = tab_at(m.column.saturating_sub(app.regions.tabs.x)) {
                    app.tab = tab;
                }
                return;
            }
            // Filter bar → start editing the filter.
            if app.tab == Tab::Packets && inside(app.regions.bar) {
                app.filter_input =
                    Some(app.filter.as_ref().map(|f| f.source.clone()).unwrap_or_default());
                return;
            }
            // Row selection inside the table body.
            if inside(app.regions.body) && m.row >= app.regions.body.y + 2 {
                let row = (m.row - app.regions.body.y - 2) as u64;
                match app.tab {
                    Tab::Packets => {
                        let target = app.view_top + row;
                        if target < app.total_rows() {
                            if let Some(l) = &mut app.live {
                                l.follow = false;
                            }
                            if app.cursor == target {
                                // Click on the selected row again = Enter:
                                // toggle the dissection/hex detail pane.
                                app.detail = !app.detail;
                                app.detail_scroll = 0;
                            } else {
                                app.cursor = target;
                            }
                        }
                    }
                    Tab::Macs => tables::click_row(app, Tab::Macs, row as usize),
                    Tab::Ports => tables::click_row(app, Tab::Ports, row as usize),
                    Tab::Flows => tables::click_row(app, Tab::Flows, row as usize),
                    Tab::Overview => {}
                }
            }
        }
        _ => {}
    }
}

/// Which tab lives at column offset `x` in the tab strip.
/// Mirrors ratatui's Tabs layout: " title │ title │ ..." (1-space padding).
fn tab_at(x: u16) -> Option<Tab> {
    let titles = ["1 OVERVIEW", "2 PACKETS", "3 MACS", "4 PORTS", "5 FLOWS"];
    let tabs = [Tab::Overview, Tab::Packets, Tab::Macs, Tab::Ports, Tab::Flows];
    let mut pos = 0u16;
    for (i, t) in titles.iter().enumerate() {
        let w = t.len() as u16 + 2; // one space padding each side
        if x < pos + w {
            return Some(tabs[i]);
        }
        pos += w + 1; // divider
    }
    None
}

fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let titles = ["1 OVERVIEW", "2 PACKETS", "3 MACS", "4 PORTS", "5 FLOWS"];
    let sel = match app.tab {
        Tab::Overview => 0,
        Tab::Packets => 1,
        Tab::Macs => 2,
        Tab::Ports => 3,
        Tab::Flows => 4,
    };
    let stats = &app.index.stats;
    let right = match &app.live {
        Some(l) => {
            let mut r = format!(
                "{} {}  {} pkts  {:.0} pkt/s  spool {}{}",
                if l.running { "● LIVE" } else { "■ STOPPED" },
                l.iface,
                stats.packets,
                if l.running { l.rate } else { 0.0 },
                litework_core::types::fmt_bytes(app.file.len()),
                if l.temp { " (temp)" } else { "" }
            );
            if l.kernel_drop > 0 {
                r.push_str(&format!("  DROPS {}", l.kernel_drop));
            }
            r
        }
        None => {
            let name = app
                .file
                .path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!(
                "{}  {} pkts  {}",
                name,
                stats.packets,
                litework_core::types::fmt_bytes(app.file.len())
            )
        }
    };
    let tabs = Tabs::new(titles.iter().map(|t| Line::from(*t)))
        .select(sel)
        .highlight_style(Style::new().bold().fg(Color::Yellow))
        .divider("│");
    f.render_widget(tabs, header);
    app.regions.tabs = header;
    let rw = right.chars().count() as u16;
    if header.width > rw + 24 {
        let area = Rect::new(header.right() - rw - 1, header.y, rw, 1);
        let style = match &app.live {
            Some(l) if l.running => Style::new().fg(Color::Green),
            Some(_) => Style::new().fg(Color::Yellow),
            None => Style::new().dim(),
        };
        f.render_widget(Line::from(right).style(style), area);
    }

    match app.tab {
        Tab::Overview => overview::draw(f, app, body),
        Tab::Packets => packets::draw(f, app, body),
        Tab::Macs | Tab::Ports | Tab::Flows => tables::draw(f, app, app.tab, body),
    }

    let hint = if app.filter_input.is_some() {
        "tab/↓↑: complete   enter: apply   esc: cancel   ?: syntax help"
    } else if app.live.is_some() {
        "space: stop/resume capture   /: filter   enter: detail   w: save   G: follow   tab/1-5: switch   q: quit"
    } else {
        match app.tab {
            Tab::Overview => "tab/1-5: switch   ?: filter help   q: quit",
            Tab::Packets => "↑↓/pgup/pgdn/g/G: move   enter: detail   /: filter   w: save to pcap   ?: help   esc: clear   tab: switch   q: quit",
            Tab::Ports | Tab::Macs => "↑↓/pgup/pgdn/g/G: move   enter: pivot   v: flows/totals   ?: filter help   tab/1-5: switch   q: quit",
            Tab::Flows => "↑↓/pgup/pgdn/g/G: move   enter: pivot to packets   ?: filter help   tab/1-5: switch   q: quit",
        }
    };
    f.render_widget(
        Line::from(hint).style(Style::new().dim()),
        footer,
    );

    if app.show_help {
        draw_help(f, f.area());
    }
    if let Some((buf, _)) = &app.save_input {
        draw_prompt(f, f.area(), " save capture as ", buf);
    } else if app.quit_confirm {
        draw_quit_confirm(f, f.area());
    }
    let _ = Block::new().borders(Borders::NONE); // keep import used
}

fn draw_prompt(f: &mut Frame, screen: Rect, title: &str, buf: &str) {
    use ratatui::widgets::{Clear, Paragraph};
    let w = (buf.len() as u16 + 8).clamp(40, screen.width.saturating_sub(4));
    let area = Rect::new(
        screen.x + (screen.width.saturating_sub(w)) / 2,
        screen.y + screen.height / 2 - 1,
        w,
        3,
    );
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(" "),
            Span::raw(buf.to_string()),
            Span::styled("█", Style::new().fg(Color::Yellow)),
        ]))
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(title.to_string())
                .title_bottom(" enter: save   ctrl-u: clear   esc: cancel "),
        ),
        area,
    );
}

fn draw_quit_confirm(f: &mut Frame, screen: Rect) {
    use ratatui::widgets::{Clear, Paragraph};
    let w = 52u16.min(screen.width.saturating_sub(4));
    let area = Rect::new(
        screen.x + (screen.width.saturating_sub(w)) / 2,
        screen.y + screen.height / 2 - 1,
        w,
        3,
    );
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" s ", Style::new().bold().fg(Color::Green)),
            Span::raw("save spooled capture   "),
            Span::styled(" d ", Style::new().bold().fg(Color::Red)),
            Span::raw("discard   "),
            Span::styled(" esc ", Style::new().bold()),
            Span::raw("back"),
        ]))
        .block(Block::new().borders(Borders::ALL).title(" quit — keep the live capture? ")),
        area,
    );
}

fn draw_help(f: &mut Frame, screen: Rect) {
    use ratatui::widgets::{Clear, Paragraph};
    let lines_src = suggest::help_lines();
    let w = 84.min(screen.width.saturating_sub(2));
    let h = (lines_src.len() as u16 + 2).min(screen.height.saturating_sub(2));
    let area = Rect::new(
        screen.x + (screen.width.saturating_sub(w)) / 2,
        screen.y + (screen.height.saturating_sub(h)) / 2,
        w,
        h,
    );
    let mut lines = Vec::new();
    for (left, right) in lines_src {
        if right.is_empty() {
            lines.push(Line::from(Span::styled(left, Style::new().bold().fg(Color::Yellow))));
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!("{left:<26}"), Style::new().bold()),
                Span::styled(right, Style::new().dim()),
            ]));
        }
    }
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" filter reference (esc to close) "),
        ),
        area,
    );
}

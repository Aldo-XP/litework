//! BYTES tab: a cross-packet byte/bit grid for reverse-engineering an
//! unknown protocol — one row per filtered packet, one column per byte, so
//! a constant magic byte and a varying counter are visually obvious at a
//! glance. Requires an active filter (`/`): the whole point is comparing
//! packets that share a structure.
//!
//! Shows the *whole frame*, not just the unrecognized payload — mac/ip/port
//! bytes are visible and inspectable too, exactly like Wireshark's tree
//! shows everything from Frame down. Three layers of fields are merged for
//! display, each only filling gaps the earlier ones left:
//!   1. known — from the existing dissection (`packets::detail_rows`)
//!   2. loaded `.ksy` (`L` key) — `kaitai::interpret`, anchored right after
//!      the known layer ends
//!   3. manual tags — `app.bytes_tab.map`, as before
//!
//! Rows come straight from `Filter.matches` — already a fully materialized
//! `Vec<PacketRecord>` (capped at `FILTER_CAP`) — so unlike the PACKETS
//! tab's virtual-scroll `Window`, there's no separate caching needed here:
//! `app.file.bytes(rec)` is an O(1) zero-copy mmap lookup, cheap enough to
//! call once per visible row per frame.

use super::packets;
use super::App;
use crossterm::event::KeyCode;
use litework_core::annotate::{self, Endian, FieldDef, FieldKind, FieldMap};
use litework_core::dissect::{dissect, field_spans};
use litework_core::kaitai;
use litework_core::types::PacketMeta;
use litework_core::PacketRecord;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

const ROW_LABEL_W: usize = 8;
const COL_W: usize = 3; // "xx "

pub struct Sandbox {
    pub bytes: Vec<u8>,
    /// Absolute (frame-relative) bit offset the scratch bytes start at.
    pub bit_start: usize,
    pub bit_cursor: usize,
}

pub struct State {
    pub map: FieldMap,
    pub cursor_bit: usize,
    pub anchor_bit: Option<usize>,
    pub bit_mode: bool,
    pub row_cursor: u64,
    pub view_top_row: u64,
    pub view_left_col: usize,
    pub sandbox: Option<Sandbox>,
    pub type_cursor: usize,
    pub name_input: Option<(FieldKind, String)>,
    pub export_choice: bool,
    pub export_input: Option<(bool, String)>,
    pub ksy_input: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            map: FieldMap::new("myproto"),
            cursor_bit: 0,
            anchor_bit: None,
            bit_mode: false,
            row_cursor: 0,
            view_top_row: 0,
            view_left_col: 0,
            sandbox: None,
            type_cursor: 0,
            name_input: None,
            export_choice: false,
            export_input: None,
            ksy_input: None,
        }
    }
}

/// The current selection as (bit_start, bit_len) — either the extent between
/// `anchor_bit` and `cursor_bit`, or a single unit (one bit in bit-mode, one
/// byte otherwise) under the cursor when nothing is actively being extended.
/// A free function (not a `&self` method) so it can be called on individual
/// fields of `app.bytes_tab` even while another field of it is already
/// mutably borrowed (e.g. inside the `name_input` prompt handler below).
fn compute_selection(cursor_bit: usize, anchor_bit: Option<usize>, bit_mode: bool) -> (usize, usize) {
    match anchor_bit {
        Some(a) => {
            let lo = a.min(cursor_bit);
            let hi = a.max(cursor_bit);
            if bit_mode {
                (lo, hi - lo + 1)
            } else {
                let lo = (lo / 8) * 8;
                let hi_end = (hi / 8) * 8 + 8;
                (lo, hi_end - lo)
            }
        }
        None => {
            if bit_mode {
                (cursor_bit, 1)
            } else {
                ((cursor_bit / 8) * 8, 8)
            }
        }
    }
}

impl State {
    pub fn selection(&self) -> (usize, usize) {
        compute_selection(self.cursor_bit, self.anchor_bit, self.bit_mode)
    }
}

/// One field ready for display — from any of the three layers.
struct MergedField {
    bit_start: usize,
    bit_len: usize,
    name: String,
    value: String,
}

fn current_row_rec(app: &App) -> Option<PacketRecord> {
    app.filter.as_ref()?.matches.get(app.bytes_tab.row_cursor as usize).copied()
}

/// Byte offset where the already-dissected header ends and the unknown
/// payload begins (see `field_spans`'s `"payload"` span) — the boundary
/// between the "known" layer and where `.ksy`/manual fields are allowed.
fn payload_start_bytes(rec: &PacketRecord, full: &[u8]) -> usize {
    field_spans(rec.linktype, full)
        .iter()
        .find(|s| s.label == "payload")
        .map(|s| s.range.start)
        .unwrap_or(full.len())
}

/// Merge known + loaded-`.ksy` + manual fields for one row, sorted by bit
/// offset. Also returns the payload boundary (bytes), used both to anchor
/// the `.ksy` layer and to block manual tagging over already-known bytes.
fn merged_fields_for_row(app: &App, rec: &PacketRecord, full: &[u8], row_idx: u64) -> (Vec<MergedField>, usize) {
    let meta = dissect(rec.linktype, full);
    // `ksy: None` here — the `.ksy` layer is added separately below with its
    // own bit-precise offsets; passing it through `detail_rows` too would
    // double it up.
    let known = packets::detail_rows(row_idx, rec, &meta, full, None);
    let mut fields: Vec<MergedField> = known
        .into_iter()
        .filter_map(|r| {
            r.span.map(|s| MergedField {
                bit_start: s.start * 8,
                bit_len: s.len() * 8,
                name: r.key.to_string(),
                value: r.value,
            })
        })
        .collect();

    let payload_start = payload_start_bytes(rec, full);

    if let Some((_, spec)) = &app.loaded_ksy {
        let payload = full.get(payload_start..).unwrap_or(&[]);
        for f in kaitai::interpret(spec, payload) {
            let value = annotate::decode(&f.kind, f.bit_start, f.bit_len, payload);
            fields.push(MergedField { bit_start: payload_start * 8 + f.bit_start, bit_len: f.bit_len, name: f.name, value });
        }
    }

    for f in app.bytes_tab.map.sorted() {
        let value = annotate::decode(&f.kind, f.bit_start, f.bit_len, full);
        fields.push(MergedField { bit_start: f.bit_start, bit_len: f.bit_len, name: f.name.clone(), value });
    }

    fields.sort_by_key(|f| f.bit_start);
    (fields, payload_start)
}

fn move_cursor(app: &mut App, delta: i64) {
    let step: i64 = if app.bytes_tab.bit_mode { 1 } else { 8 };
    let new = app.bytes_tab.cursor_bit as i64 + delta * step;
    app.bytes_tab.cursor_bit = new.max(0) as usize;
}

fn candidates_for_cursor(app: &App) -> Vec<(FieldKind, String)> {
    let Some(rec) = current_row_rec(app) else { return Vec::new() };
    let full = app.file.bytes(&rec);
    let (bit_start, bit_len) = app.bytes_tab.selection();
    annotate::candidates(bit_start, bit_len, full)
}

fn start_naming(app: &mut App) {
    let (bit_start, bit_len) = app.bytes_tab.selection();
    let sel_end = bit_start + bit_len;
    let Some(rec) = current_row_rec(app) else {
        app.status = Some("no rows".into());
        return;
    };
    let full = app.file.bytes(&rec).to_vec();
    let (fields, payload_start) = merged_fields_for_row(app, &rec, &full, app.bytes_tab.row_cursor);
    if bit_start < payload_start * 8 {
        app.status = Some("already dissected — can't tag inside the known header".into());
        return;
    }
    if let Some(f) = fields.iter().find(|f| f.bit_start < sel_end && bit_start < f.bit_start + f.bit_len) {
        app.status = Some(format!("overlaps '{}' — already identified", f.name));
        return;
    }
    let cands = annotate::candidates(bit_start, bit_len, &full);
    let Some((kind, _)) = cands.get(app.bytes_tab.type_cursor.min(cands.len().saturating_sub(1))) else {
        app.status = Some("nothing to tag here".into());
        return;
    };
    app.bytes_tab.name_input = Some((kind.clone(), String::new()));
}

fn jump_to_payload(app: &mut App) {
    let Some(rec) = current_row_rec(app) else { return };
    let full = app.file.bytes(&rec).to_vec();
    let start = payload_start_bytes(&rec, &full);
    app.bytes_tab.cursor_bit = start * 8;
    app.bytes_tab.anchor_bit = None;
}

fn start_sandbox(app: &mut App) {
    let Some(rec) = current_row_rec(app) else {
        app.status = Some("no rows".into());
        return;
    };
    let full = app.file.bytes(&rec).to_vec();
    let (bit_start, bit_len) = app.bytes_tab.selection();
    let byte_start = bit_start / 8;
    let byte_end = (bit_start + bit_len).div_ceil(8);
    let bytes = full.get(byte_start..byte_end).unwrap_or(&[]).to_vec();
    if bytes.is_empty() {
        app.status = Some("nothing selected".into());
        return;
    }
    app.bytes_tab.sandbox = Some(Sandbox { bytes, bit_start: byte_start * 8, bit_cursor: bit_start });
}

fn sandbox_move(app: &mut App, delta: i64) {
    let Some(sb) = &mut app.bytes_tab.sandbox else { return };
    let max_bit = sb.bit_start + sb.bytes.len() * 8;
    let new = (sb.bit_cursor as i64 + delta).clamp(sb.bit_start as i64, max_bit as i64 - 1);
    sb.bit_cursor = new as usize;
}

fn sandbox_flip_bit(app: &mut App) {
    let Some(sb) = &mut app.bytes_tab.sandbox else { return };
    let local = sb.bit_cursor - sb.bit_start;
    sb.bytes[local / 8] ^= 0x80 >> (local % 8);
}

fn do_export(app: &mut App, is_lua: bool, name: &str) {
    let content = if is_lua {
        let meta = current_row_rec(app)
            .map(|rec| dissect(rec.linktype, app.file.bytes(&rec)))
            .unwrap_or_else(PacketMeta::empty);
        annotate::to_lua(&app.bytes_tab.map, &meta)
    } else {
        annotate::to_kaitai(&app.bytes_tab.map)
    };
    match std::fs::write(name, content) {
        Ok(()) => app.status = Some(format!("exported → {name}")),
        Err(e) => app.status = Some(format!("export failed: {e}")),
    }
}

fn do_load_ksy(app: &mut App, path: &str) {
    if path.trim().is_empty() {
        let had = app.loaded_ksy.take().is_some();
        app.status = Some(if had { "ksy unloaded".into() } else { "no ksy was loaded".into() });
        return;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => match kaitai::parse(&text) {
            Ok(spec) => {
                app.status = Some(format!("loaded '{}' from {path}", spec.id));
                app.loaded_ksy = Some((spec.id.clone(), spec));
            }
            Err(e) => app.status = Some(format!("ksy parse error: {e}")),
        },
        Err(e) => app.status = Some(format!("couldn't read {path}: {e}")),
    }
}

pub fn handle_key(app: &mut App, code: KeyCode) {
    if app.filter.is_none() {
        return;
    }
    app.status = None;

    if let Some((kind, buf)) = &mut app.bytes_tab.name_input {
        match code {
            KeyCode::Esc => app.bytes_tab.name_input = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Enter => {
                if !buf.trim().is_empty() {
                    let (bit_start, bit_len) =
                        compute_selection(app.bytes_tab.cursor_bit, app.bytes_tab.anchor_bit, app.bytes_tab.bit_mode);
                    let field = FieldDef { name: buf.trim().to_string(), bit_start, bit_len, kind: kind.clone() };
                    let ok = app.bytes_tab.map.insert(field);
                    app.status =
                        Some(if ok { "field added".into() } else { "overlaps an existing field".into() });
                    app.bytes_tab.anchor_bit = None;
                }
                app.bytes_tab.name_input = None;
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return;
    }

    if let Some((is_lua, buf)) = &mut app.bytes_tab.export_input {
        match code {
            KeyCode::Esc => app.bytes_tab.export_input = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Enter => {
                let (is_lua, name) = (*is_lua, buf.clone());
                app.bytes_tab.export_input = None;
                do_export(app, is_lua, &name);
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return;
    }

    if let Some(buf) = &mut app.bytes_tab.ksy_input {
        match code {
            KeyCode::Esc => app.bytes_tab.ksy_input = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Enter => {
                let path = buf.clone();
                app.bytes_tab.ksy_input = None;
                do_load_ksy(app, &path);
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return;
    }

    if app.bytes_tab.export_choice {
        match code {
            KeyCode::Char('l') => {
                app.bytes_tab.export_choice = false;
                app.bytes_tab.export_input = Some((true, "litework-proto.lua".into()));
            }
            KeyCode::Char('k') => {
                app.bytes_tab.export_choice = false;
                app.bytes_tab.export_input = Some((false, "litework-proto.ksy".into()));
            }
            KeyCode::Esc => app.bytes_tab.export_choice = false,
            _ => {}
        }
        return;
    }

    if app.bytes_tab.sandbox.is_some() {
        match code {
            KeyCode::Esc => app.bytes_tab.sandbox = None,
            KeyCode::Left | KeyCode::Char('h') => sandbox_move(app, -1),
            KeyCode::Right | KeyCode::Char('l') => sandbox_move(app, 1),
            KeyCode::Char(' ') | KeyCode::Enter => sandbox_flip_bit(app),
            KeyCode::Char('r') => {
                if let Some(sb) = &mut app.bytes_tab.sandbox {
                    sb.bytes.reverse();
                }
            }
            _ => {}
        }
        return;
    }

    let total_rows = app.filter.as_ref().map(|f| f.matches.len() as u64).unwrap_or(0);
    match code {
        KeyCode::Char('h') | KeyCode::Left => move_cursor(app, -1),
        KeyCode::Char('l') | KeyCode::Right => move_cursor(app, 1),
        KeyCode::Char('j') | KeyCode::Down => {
            app.bytes_tab.row_cursor = (app.bytes_tab.row_cursor + 1).min(total_rows.saturating_sub(1));
        }
        KeyCode::Char('k') | KeyCode::Up => app.bytes_tab.row_cursor = app.bytes_tab.row_cursor.saturating_sub(1),
        KeyCode::PageDown => {
            app.bytes_tab.row_cursor = (app.bytes_tab.row_cursor + 20).min(total_rows.saturating_sub(1));
        }
        KeyCode::PageUp => app.bytes_tab.row_cursor = app.bytes_tab.row_cursor.saturating_sub(20),
        KeyCode::Char('g') | KeyCode::Home => app.bytes_tab.row_cursor = 0,
        KeyCode::Char('G') | KeyCode::End => app.bytes_tab.row_cursor = total_rows.saturating_sub(1),
        KeyCode::Char('b') => app.bytes_tab.bit_mode = !app.bytes_tab.bit_mode,
        KeyCode::Char('v') => {
            app.bytes_tab.anchor_bit = if app.bytes_tab.anchor_bit.is_some() {
                None
            } else {
                Some(app.bytes_tab.cursor_bit)
            };
        }
        KeyCode::Char('c') => {
            let n = candidates_for_cursor(app).len();
            if n > 0 {
                app.bytes_tab.type_cursor = (app.bytes_tab.type_cursor + 1) % n;
            }
        }
        KeyCode::Enter => start_naming(app),
        KeyCode::Char('u') => {
            app.status = app.bytes_tab.map.undo().map(|f| format!("undid '{}'", f.name));
        }
        KeyCode::Char('d') => {
            if app.bytes_tab.map.remove_at(app.bytes_tab.cursor_bit) {
                app.status = Some("field removed".into());
            }
        }
        KeyCode::Char('s') => start_sandbox(app),
        KeyCode::Char('f') => jump_to_payload(app),
        KeyCode::Char('x') => app.bytes_tab.export_choice = true,
        KeyCode::Char('L') => app.bytes_tab.ksy_input = Some(String::new()),
        KeyCode::Esc => app.bytes_tab.anchor_bit = None,
        _ => {}
    }
}

fn kind_name(k: &FieldKind) -> &'static str {
    match k {
        FieldKind::UInt(Endian::Big) => "uint-be",
        FieldKind::UInt(Endian::Little) => "uint-le",
        FieldKind::Int(Endian::Big) => "int-be",
        FieldKind::Int(Endian::Little) => "int-le",
        FieldKind::Ipv4 => "ipv4",
        FieldKind::Ipv6 => "ipv6",
        FieldKind::Mac => "mac",
        FieldKind::Ascii => "ascii",
        FieldKind::Bytes => "bytes",
        FieldKind::Flag => "flag",
    }
}

fn fit(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else if width >= 1 {
        let truncated: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        String::new()
    }
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    if app.filter.is_none() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no filter — press / to filter (e.g. port == 5000), then compare matching packets byte-by-byte here",
                Style::new().dim(),
            ))),
            area,
        );
        return;
    }
    let total_rows = app.filter.as_ref().unwrap().matches.len() as u64;
    if total_rows == 0 {
        f.render_widget(Paragraph::new("0 matches"), area);
        return;
    }
    app.bytes_tab.row_cursor = app.bytes_tab.row_cursor.min(total_rows - 1);

    let [grid_area, info_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Length(9)]).areas(area);
    draw_grid(f, app, grid_area);
    draw_info(f, app, info_area);

    if let Some((_, buf)) = &app.bytes_tab.name_input {
        super::draw_prompt(f, f.area(), " name this field ", buf);
    } else if let Some((_, buf)) = &app.bytes_tab.export_input {
        super::draw_prompt(f, f.area(), " export filename ", buf);
    } else if let Some(buf) = &app.bytes_tab.ksy_input {
        super::draw_prompt(f, f.area(), " load .ksy (empty = unload) ", buf);
    } else if app.bytes_tab.export_choice {
        draw_export_choice(f, f.area());
    }
}

fn draw_row_cells(
    app: &App,
    full: &[u8],
    fields: &[MergedField],
    left: usize,
    n_cols: usize,
    is_cursor_row: bool,
) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let (sel_start, sel_len) = app.bytes_tab.selection();
    let sel_end = sel_start + sel_len;
    let end = left + n_cols;
    let mut c = left;
    while c < end {
        let bit0 = c * 8;
        if let Some(field) = fields.iter().find(|fd| bit0 >= fd.bit_start && bit0 < fd.bit_start + fd.bit_len) {
            let field_first_col = field.bit_start / 8;
            let field_col_width = field.bit_len.div_ceil(8);
            let field_end_col = field_first_col + field_col_width;
            if c == field_first_col {
                let visible_cols = field_end_col.min(end) - c;
                let width = (visible_cols * COL_W).saturating_sub(1);
                let text = fit(&field.value, width);
                spans.push(Span::styled(format!("{text:<width$} "), Style::new().fg(Color::Cyan)));
                c += visible_cols;
            } else {
                let visible_cols = field_end_col.min(end) - c;
                spans.push(Span::styled(" ".repeat(visible_cols * COL_W), Style::new().fg(Color::Cyan)));
                c += visible_cols;
            }
            continue;
        }
        let is_cursor_col = is_cursor_row && c == app.bytes_tab.cursor_bit / 8;
        let in_sel = is_cursor_row && bit0 < sel_end && bit0 + 8 > sel_start;
        let text = match full.get(c) {
            Some(b) => format!("{b:02x}"),
            None => "..".to_string(),
        };
        let style = if is_cursor_col {
            Style::new().bg(Color::Yellow).fg(Color::Black)
        } else if in_sel {
            Style::new().bg(Color::DarkGray)
        } else {
            Style::new()
        };
        spans.push(Span::styled(format!("{text:<width$}", width = COL_W), style));
        c += 1;
    }
    spans
}

fn draw_grid(f: &mut Frame, app: &mut App, area: Rect) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let usable = inner_width.saturating_sub(ROW_LABEL_W);
    let n_cols = (usable / COL_W).max(1);

    let cursor_byte = app.bytes_tab.cursor_bit / 8;
    if cursor_byte < app.bytes_tab.view_left_col {
        app.bytes_tab.view_left_col = cursor_byte;
    } else if cursor_byte >= app.bytes_tab.view_left_col + n_cols {
        app.bytes_tab.view_left_col = cursor_byte + 1 - n_cols;
    }
    let left = app.bytes_tab.view_left_col;

    let page = (area.height.saturating_sub(3) as u64).max(1);
    if app.bytes_tab.row_cursor < app.bytes_tab.view_top_row {
        app.bytes_tab.view_top_row = app.bytes_tab.row_cursor;
    } else if app.bytes_tab.row_cursor >= app.bytes_tab.view_top_row + page {
        app.bytes_tab.view_top_row = app.bytes_tab.row_cursor + 1 - page;
    }
    let top = app.bytes_tab.view_top_row;

    let mut lines = Vec::new();
    let mut header = vec![Span::raw(" ".repeat(ROW_LABEL_W))];
    for c in left..left + n_cols {
        header.push(Span::styled(format!("{c:<width$}", width = COL_W), Style::new().dim().bold()));
    }
    lines.push(Line::from(header));

    let total = app.filter.as_ref().unwrap().matches.len() as u64;
    let last = (top + page).min(total);
    for row_idx in top..last {
        let rec = app.filter.as_ref().unwrap().matches[row_idx as usize];
        let full = app.file.bytes(&rec);
        let (fields, _payload_start) = merged_fields_for_row(app, &rec, full, row_idx);
        let is_cursor_row = row_idx == app.bytes_tab.row_cursor;

        let mut spans = vec![Span::styled(
            format!("{row_idx:<width$}", width = ROW_LABEL_W),
            if is_cursor_row { Style::new().bold() } else { Style::new().dim() },
        )];
        spans.extend(draw_row_cells(app, full, &fields, left, n_cols, is_cursor_row));
        lines.push(Line::from(spans));
    }

    let ksy_note = match &app.loaded_ksy {
        Some((id, _)) => format!("ksy: {id}"),
        None => "no ksy".into(),
    };
    let title = format!(" bytes — {total} matches, {} tagged, {ksy_note} ", app.bytes_tab.map.fields.len());
    f.render_widget(Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(title)), area);
}

fn draw_info(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(msg) = &app.status {
        lines.push(Line::from(Span::styled(format!("✓ {msg}"), Style::new().fg(Color::Green))));
    }
    let rec = current_row_rec(app);
    let full: Vec<u8> = rec.map(|rec| app.file.bytes(&rec).to_vec()).unwrap_or_default();
    let (fields, payload_start) = match rec {
        Some(rec) => merged_fields_for_row(app, &rec, &full, app.bytes_tab.row_cursor),
        None => (Vec::new(), 0),
    };

    if let Some(sb) = &app.bytes_tab.sandbox {
        let local = sb.bit_cursor - sb.bit_start;
        lines.push(Line::from(Span::styled(
            format!(
                "SANDBOX  bytes: {}   uint(BE): {}   uint(LE): {}   ascii: {}   [h/l: move bit {local}] [space: flip] [r: reverse bytes] [esc: exit]",
                sb.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                annotate::decode(&FieldKind::UInt(Endian::Big), 0, sb.bytes.len() * 8, &sb.bytes),
                annotate::decode(&FieldKind::UInt(Endian::Little), 0, sb.bytes.len() * 8, &sb.bytes),
                annotate::decode(&FieldKind::Ascii, 0, sb.bytes.len() * 8, &sb.bytes),
            ),
            Style::new().fg(Color::Magenta).bold(),
        )));
    } else {
        let (bit_start, bit_len) = app.bytes_tab.selection();
        let sel_end = bit_start + bit_len;
        if let Some(field) = fields.iter().find(|fd| fd.bit_start < sel_end && bit_start < fd.bit_start + fd.bit_len) {
            lines.push(Line::from(format!(
                "already identified: {}  bit {} len {} = {}",
                field.name, field.bit_start, field.bit_len, field.value
            )));
        } else if bit_start < payload_start * 8 {
            lines.push(Line::from(Span::styled(
                format!("selection: bit {bit_start} len {bit_len}   (inside the known header)"),
                Style::new().dim(),
            )));
        } else {
            let cands = annotate::candidates(bit_start, bit_len, &full);
            let mut spans = vec![Span::raw(format!("selection: bit {bit_start} len {bit_len}   "))];
            if cands.is_empty() {
                spans.push(Span::styled("(nothing to tag)", Style::new().dim()));
            } else {
                let sel_idx = app.bytes_tab.type_cursor % cands.len();
                for (i, (kind, val)) in cands.iter().enumerate() {
                    let style = if i == sel_idx {
                        Style::new().bg(Color::Yellow).fg(Color::Black)
                    } else {
                        Style::new().dim()
                    };
                    spans.push(Span::styled(format!(" {}={} ", kind_name(kind), val), style));
                }
            }
            lines.push(Line::from(spans));
        }
    }
    lines.push(Line::from(""));

    for field in &fields {
        lines.push(Line::from(format!(
            "  {:<16} bit {:<5} len {:<4} = {}",
            field.name, field.bit_start, field.bit_len, field.value
        )));
    }

    f.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" fields (row-cursor decode) ")),
        area,
    );
}

fn draw_export_choice(f: &mut Frame, screen: Rect) {
    use ratatui::widgets::Clear;
    let w = 46u16.min(screen.width.saturating_sub(4));
    let area = Rect::new(
        screen.x + (screen.width.saturating_sub(w)) / 2,
        screen.y + screen.height / 2 - 1,
        w,
        3,
    );
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" l ", Style::new().bold().fg(Color::Green)),
            Span::raw("lua dissector   "),
            Span::styled(" k ", Style::new().bold().fg(Color::Green)),
            Span::raw("kaitai .ksy   "),
            Span::styled(" esc ", Style::new().bold()),
            Span::raw("cancel"),
        ]))
        .block(Block::new().borders(Borders::ALL).title(" export as ")),
        area,
    );
}

//! Interactive byte/bit protocol reverse-engineering: a user-built map of
//! named, typed byte/bit ranges over an otherwise-unknown payload, plus
//! codegen to export that discovery as a Wireshark Lua dissector or a
//! Kaitai Struct (`.ksy`) definition.
//!
//! Bits are numbered MSB-first within each byte (bit 0 = 0x80), matching how
//! protocol spec diagrams and Wireshark itself number bits. `bit_start`/
//! `bit_len` are relative to whatever anchor the caller chose (the TUI
//! anchors to the detected payload start by default — see
//! `crate::dissect::field_spans`).

use crate::types::PacketMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// Unsigned integer. `bit_len` 1..=64; byte-aligned lengths use `endian`,
    /// sub-byte lengths are plain bitfields (endian is meaningless there).
    UInt(Endian),
    /// Signed integer, byte-aligned only (two's complement).
    Int(Endian),
    /// `bit_len` must be 32, byte-aligned.
    Ipv4,
    /// `bit_len` must be 128, byte-aligned.
    Ipv6,
    /// `bit_len` must be 48, byte-aligned.
    Mac,
    /// `bit_len` a multiple of 8, byte-aligned.
    Ascii,
    /// Raw hex bytes. `bit_len` a multiple of 8, byte-aligned.
    Bytes,
    /// A single bit, shown as true/false.
    Flag,
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub bit_start: usize,
    pub bit_len: usize,
    pub kind: FieldKind,
}

impl FieldDef {
    fn bit_end(&self) -> usize {
        self.bit_start + self.bit_len
    }
}

/// A user-built map of fields for one (presumably unknown) protocol,
/// discovered interactively over one representative packet's bytes.
#[derive(Debug, Default, Clone)]
pub struct FieldMap {
    pub proto_name: String,
    /// Insertion order (so "undo last" is a plain `pop`) — use `sorted()`
    /// for anything that needs byte order (rendering, export).
    pub fields: Vec<FieldDef>,
}

impl FieldMap {
    pub fn new(proto_name: impl Into<String>) -> Self {
        FieldMap { proto_name: proto_name.into(), fields: Vec::new() }
    }

    /// Insert a field. Fails (returns `false`, no change) if it overlaps an
    /// already-tagged field.
    pub fn insert(&mut self, field: FieldDef) -> bool {
        let end = field.bit_end();
        if self.fields.iter().any(|f| field.bit_start < f.bit_end() && f.bit_start < end) {
            return false;
        }
        self.fields.push(field);
        true
    }

    /// Remove the most recently added field.
    pub fn undo(&mut self) -> Option<FieldDef> {
        self.fields.pop()
    }

    /// Remove whichever field covers bit `bit`, if any.
    pub fn remove_at(&mut self, bit: usize) -> bool {
        match self.fields.iter().position(|f| bit >= f.bit_start && bit < f.bit_end()) {
            Some(i) => {
                self.fields.remove(i);
                true
            }
            None => false,
        }
    }

    /// The field covering bit `bit`, if any.
    pub fn field_at(&self, bit: usize) -> Option<&FieldDef> {
        self.fields.iter().find(|f| bit >= f.bit_start && bit < f.bit_end())
    }

    /// Fields in byte/bit order — what rendering and export want.
    pub fn sorted(&self) -> Vec<&FieldDef> {
        let mut v: Vec<&FieldDef> = self.fields.iter().collect();
        v.sort_by_key(|f| f.bit_start);
        v
    }
}

// ---------------------------------------------------------------- decoding

/// Generic MSB-first bit extraction into a `u64` (bit 0 of the range is the
/// most significant bit of the result). `None` if the range runs past `data`
/// or `bit_len` exceeds 64.
fn extract_bits(data: &[u8], bit_start: usize, bit_len: usize) -> Option<u64> {
    if bit_len == 0 || bit_len > 64 {
        return None;
    }
    let mut val: u64 = 0;
    for i in 0..bit_len {
        let bit_idx = bit_start + i;
        let byte = *data.get(bit_idx / 8)?;
        let bit = (byte >> (7 - bit_idx % 8)) & 1;
        val = (val << 1) | bit as u64;
    }
    Some(val)
}

/// Like `extract_bits`, but byte-aligned ranges honor `endian` (whole bytes
/// are reordered; bit order within each byte never changes).
pub(crate) fn extract_uint(data: &[u8], bit_start: usize, bit_len: usize, endian: Endian) -> Option<u64> {
    if bit_len == 0 || bit_len > 64 {
        return None;
    }
    if bit_start.is_multiple_of(8) && bit_len.is_multiple_of(8) {
        let start = bit_start / 8;
        let len = bit_len / 8;
        let bytes = data.get(start..start + len)?;
        let mut buf = [0u8; 8];
        let dst = &mut buf[8 - len..];
        match endian {
            Endian::Big => dst.copy_from_slice(bytes),
            Endian::Little => {
                for (d, s) in dst.iter_mut().zip(bytes.iter().rev()) {
                    *d = *s;
                }
            }
        }
        Some(u64::from_be_bytes(buf))
    } else {
        extract_bits(data, bit_start, bit_len)
    }
}

fn sign_extend(val: u64, bit_len: usize) -> i64 {
    if bit_len >= 64 {
        return val as i64;
    }
    let sign_bit = 1u64 << (bit_len - 1);
    if val & sign_bit != 0 {
        (val as i64) - (1i64 << bit_len)
    } else {
        val as i64
    }
}

fn fmt_bytes_range(data: &[u8], bit_start: usize, bit_len: usize) -> Option<&[u8]> {
    if !bit_start.is_multiple_of(8) || !bit_len.is_multiple_of(8) {
        return None;
    }
    data.get(bit_start / 8..bit_start / 8 + bit_len / 8)
}

/// Decode `data`'s bits `[bit_start, bit_start+bit_len)` as `kind`.
/// Never panics — out-of-range or malformed requests just yield `"?"`.
pub fn decode(kind: &FieldKind, bit_start: usize, bit_len: usize, data: &[u8]) -> String {
    match kind {
        FieldKind::UInt(e) => match extract_uint(data, bit_start, bit_len, *e) {
            Some(v) => format!("{v} (0x{v:x})"),
            None => "?".into(),
        },
        FieldKind::Int(e) => match extract_uint(data, bit_start, bit_len, *e) {
            Some(v) => sign_extend(v, bit_len).to_string(),
            None => "?".into(),
        },
        FieldKind::Flag => match extract_bits(data, bit_start, bit_len) {
            Some(v) => (v != 0).to_string(),
            None => "?".into(),
        },
        FieldKind::Ipv4 => match fmt_bytes_range(data, bit_start, bit_len) {
            Some([a, b, c, d]) => format!("{a}.{b}.{c}.{d}"),
            _ => "?".into(),
        },
        FieldKind::Ipv6 => match fmt_bytes_range(data, bit_start, bit_len) {
            Some(b) if b.len() == 16 => {
                let arr: [u8; 16] = b.try_into().unwrap();
                std::net::Ipv6Addr::from(arr).to_string()
            }
            _ => "?".into(),
        },
        FieldKind::Mac => match fmt_bytes_range(data, bit_start, bit_len) {
            Some([a, b, c, d, e, f]) => format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}"),
            _ => "?".into(),
        },
        FieldKind::Ascii => match fmt_bytes_range(data, bit_start, bit_len) {
            Some(b) => b
                .iter()
                .map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' })
                .collect(),
            None => "?".into(),
        },
        FieldKind::Bytes => match fmt_bytes_range(data, bit_start, bit_len) {
            Some(b) => b.iter().map(|c| format!("{c:02x}")).collect::<Vec<_>>().join(":"),
            None => "?".into(),
        },
    }
}

/// Plausible readings for a not-yet-tagged selection, for the TUI's
/// `Tab`-cycle-to-choose-a-type flow and the sandbox's live status line.
pub fn candidates(bit_start: usize, bit_len: usize, data: &[u8]) -> Vec<(FieldKind, String)> {
    let mut out = Vec::new();
    let byte_aligned = bit_start.is_multiple_of(8) && bit_len.is_multiple_of(8);
    let push = |out: &mut Vec<(FieldKind, String)>, k: FieldKind| {
        let s = decode(&k, bit_start, bit_len, data);
        out.push((k, s));
    };

    if bit_len == 1 {
        push(&mut out, FieldKind::Flag);
        return out; // a single bit is only ever a flag
    }
    if bit_len <= 64 {
        push(&mut out, FieldKind::UInt(Endian::Big));
        if byte_aligned && bit_len > 8 {
            push(&mut out, FieldKind::UInt(Endian::Little));
        }
        if byte_aligned {
            push(&mut out, FieldKind::Int(Endian::Big));
            if bit_len > 8 {
                push(&mut out, FieldKind::Int(Endian::Little));
            }
        }
    }
    if byte_aligned {
        match bit_len {
            32 => push(&mut out, FieldKind::Ipv4),
            128 => push(&mut out, FieldKind::Ipv6),
            48 => push(&mut out, FieldKind::Mac),
            _ => {}
        }
        if bit_len.is_multiple_of(8) && bit_len > 0 {
            push(&mut out, FieldKind::Ascii);
            push(&mut out, FieldKind::Bytes);
        }
    }
    out
}

// ---------------------------------------------------------------- export

/// Sanitize a user-given name into a valid Kaitai/Lua identifier.
fn slug(name: &str) -> String {
    let mut s: String = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let s = s.trim_matches('_').to_string();
    if s.is_empty() {
        "field".into()
    } else if s.chars().next().unwrap().is_ascii_digit() {
        format!("f_{s}")
    } else {
        s
    }
}

fn kaitai_int_type(bytes: usize, signed: bool, endian: Endian) -> String {
    let base = if signed { 's' } else { 'u' };
    if bytes == 1 {
        format!("{base}1")
    } else {
        let suf = match endian {
            Endian::Big => "be",
            Endian::Little => "le",
        };
        format!("{base}{bytes}{suf}")
    }
}

fn kaitai_field(f: &FieldDef) -> String {
    let id = slug(&f.name);
    match &f.kind {
        FieldKind::UInt(_) | FieldKind::Int(_) if !f.bit_len.is_multiple_of(8) => {
            format!("  - id: {id}\n    type: b{}\n", f.bit_len)
        }
        FieldKind::UInt(e) => format!("  - id: {id}\n    type: {}\n", kaitai_int_type(f.bit_len / 8, false, *e)),
        FieldKind::Int(e) => format!("  - id: {id}\n    type: {}\n", kaitai_int_type(f.bit_len / 8, true, *e)),
        FieldKind::Flag => format!("  - id: {id}\n    type: b1\n"),
        FieldKind::Ipv4 => format!("  - id: {id}\n    type: u4be\n    doc: IPv4 address\n"),
        FieldKind::Ipv6 => format!("  - id: {id}\n    size: 16\n    doc: IPv6 address\n"),
        FieldKind::Mac => format!("  - id: {id}\n    size: 6\n    doc: MAC address\n"),
        FieldKind::Ascii => {
            format!("  - id: {id}\n    type: str\n    size: {}\n    encoding: ASCII\n", f.bit_len / 8)
        }
        FieldKind::Bytes => format!("  - id: {id}\n    size: {}\n", f.bit_len / 8),
    }
}

/// Generate a Kaitai Struct (`.ksy`) definition covering every tagged field,
/// with byte-accurate `unknownN` filler for untagged gaps.
pub fn to_kaitai(map: &FieldMap) -> String {
    let mut out = format!("meta:\n  id: {}\n", slug(&map.proto_name));
    out.push_str("seq:\n");
    let mut cursor = 0usize;
    let mut gap_n = 0;
    for f in map.sorted() {
        if f.bit_start > cursor {
            let gap = f.bit_start - cursor;
            if gap.is_multiple_of(8) {
                out.push_str(&format!("  - id: unknown{gap_n}\n    size: {}\n", gap / 8));
            } else {
                out.push_str(&format!("  - id: unknown{gap_n}\n    type: b{gap}\n"));
            }
            gap_n += 1;
        }
        out.push_str(&kaitai_field(f));
        cursor = f.bit_end();
    }
    out
}

fn lua_bitmask(f: &FieldDef) -> u32 {
    let start_in_byte = f.bit_start % 8;
    let mut mask: u32 = 0;
    for i in 0..f.bit_len {
        let pos = start_in_byte + i;
        if pos >= 8 {
            break; // cross-byte bitfields: out of scope, best-effort mask
        }
        mask |= 1 << (7 - pos);
    }
    mask
}

fn lua_protofield_decl(var: &str, full_name: &str, f: &FieldDef) -> String {
    let label = &f.name;
    match &f.kind {
        FieldKind::Flag => {
            format!("local {var} = ProtoField.bool(\"{full_name}\", \"{label}\", 8, nil, 0x{:02x})", lua_bitmask(f))
        }
        FieldKind::UInt(_) if !f.bit_len.is_multiple_of(8) => format!(
            "local {var} = ProtoField.uint8(\"{full_name}\", \"{label}\", base.HEX, nil, 0x{:02x})",
            lua_bitmask(f)
        ),
        FieldKind::UInt(_) => {
            format!("local {var} = ProtoField.uint{}(\"{full_name}\", \"{label}\", base.DEC)", f.bit_len)
        }
        FieldKind::Int(_) => {
            format!("local {var} = ProtoField.int{}(\"{full_name}\", \"{label}\", base.DEC)", f.bit_len)
        }
        FieldKind::Ipv4 => format!("local {var} = ProtoField.ipv4(\"{full_name}\", \"{label}\")"),
        FieldKind::Ipv6 => format!("local {var} = ProtoField.ipv6(\"{full_name}\", \"{label}\")"),
        FieldKind::Mac => format!("local {var} = ProtoField.ether(\"{full_name}\", \"{label}\")"),
        FieldKind::Ascii => format!("local {var} = ProtoField.string(\"{full_name}\", \"{label}\")"),
        FieldKind::Bytes => format!("local {var} = ProtoField.bytes(\"{full_name}\", \"{label}\")"),
    }
}

/// Generate a Wireshark Lua dissector script covering every tagged field.
/// Bitfields use `ProtoField`'s own bitmask parameter (how real Lua
/// dissectors express them). The port-registration line is pre-filled from
/// `meta` (the packet the map was built against carries a real observed
/// protocol/port) rather than left as a guess.
pub fn to_lua(map: &FieldMap, meta: &PacketMeta) -> String {
    let proto_id = slug(&map.proto_name);
    let sorted = map.sorted();
    let mut out = format!("local {proto_id} = Proto(\"{proto_id}\", \"{}\")\n\n", map.proto_name);

    let mut var_names = Vec::with_capacity(sorted.len());
    for f in &sorted {
        let var = format!("f_{}", slug(&f.name));
        let full = format!("{proto_id}.{}", slug(&f.name));
        out.push_str(&lua_protofield_decl(&var, &full, f));
        out.push('\n');
        var_names.push(var);
    }
    out.push('\n');
    out.push_str(&format!("{proto_id}.fields = {{ {} }}\n\n", var_names.join(", ")));

    out.push_str(&format!("function {proto_id}.dissector(buffer, pinfo, tree)\n"));
    out.push_str(&format!("  pinfo.cols.protocol = \"{}\"\n", map.proto_name.to_uppercase()));
    out.push_str(&format!("  local subtree = tree:add({proto_id}, buffer(), \"{}\")\n", map.proto_name));
    for (f, var) in sorted.iter().zip(&var_names) {
        let byte_start = f.bit_start / 8;
        let byte_len = f.bit_len.div_ceil(8).max(1);
        let add = if matches!(f.kind, FieldKind::UInt(Endian::Little) | FieldKind::Int(Endian::Little)) {
            "add_le"
        } else {
            "add"
        };
        out.push_str(&format!("  subtree:{add}({var}, buffer({byte_start},{byte_len}))\n"));
    }
    out.push_str("end\n");

    if let (Some(proto), Some(port)) = (meta.ip_proto, meta.dport) {
        if let Some(table) = match proto {
            6 => Some("tcp.port"),
            17 => Some("udp.port"),
            _ => None,
        } {
            out.push_str(&format!("\nDissectorTable.get(\"{table}\"):add({port}, {proto_id})\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_uint_byte_aligned_endianness() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(extract_uint(&data, 0, 32, Endian::Big), Some(0x01020304));
        assert_eq!(extract_uint(&data, 0, 32, Endian::Little), Some(0x04030201));
        assert_eq!(extract_uint(&data, 8, 16, Endian::Big), Some(0x0203));
        assert_eq!(extract_uint(&data, 8, 16, Endian::Little), Some(0x0302));
    }

    #[test]
    fn extract_bits_sub_byte() {
        // 0b1011_0010: bits (MSB-first) = 1,0,1,1,0,0,1,0
        let data = [0b1011_0010];
        assert_eq!(extract_bits(&data, 0, 1), Some(1));
        assert_eq!(extract_bits(&data, 1, 1), Some(0));
        assert_eq!(extract_bits(&data, 0, 4), Some(0b1011));
        assert_eq!(extract_bits(&data, 4, 4), Some(0b0010));
        assert_eq!(extract_bits(&data, 6, 2), Some(0b10));
    }

    #[test]
    fn decode_kinds() {
        let ip = [10, 0, 0, 1];
        assert_eq!(decode(&FieldKind::Ipv4, 0, 32, &ip), "10.0.0.1");

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(decode(&FieldKind::Mac, 0, 48, &mac), "aa:bb:cc:dd:ee:ff");

        let text = b"HELLO!!!";
        assert_eq!(decode(&FieldKind::Ascii, 0, 64, text), "HELLO!!!");

        let neg = [0xff, 0xff]; // -1 as i16
        assert_eq!(decode(&FieldKind::Int(Endian::Big), 0, 16, &neg), "-1");

        let flags = [0b0000_0100]; // bit 5 (0-indexed from MSB) set
        assert_eq!(decode(&FieldKind::Flag, 5, 1, &flags), "true");
        assert_eq!(decode(&FieldKind::Flag, 4, 1, &flags), "false");

        // out of range never panics
        assert_eq!(decode(&FieldKind::UInt(Endian::Big), 100, 32, &ip), "?");
    }

    #[test]
    fn candidates_cover_expected_types() {
        let four_bytes = [10, 0, 0, 1];
        let kinds: Vec<_> = candidates(0, 32, &four_bytes).into_iter().map(|(k, _)| k).collect();
        assert!(kinds.contains(&FieldKind::Ipv4));
        assert!(kinds.iter().any(|k| matches!(k, FieldKind::UInt(Endian::Big))));
        assert!(kinds.iter().any(|k| matches!(k, FieldKind::UInt(Endian::Little))));

        let one_bit = [0xffu8];
        let kinds: Vec<_> = candidates(0, 1, &one_bit).into_iter().map(|(k, _)| k).collect();
        assert_eq!(kinds, vec![FieldKind::Flag]);
    }

    #[test]
    fn field_map_rejects_overlap_and_undoes() {
        let mut map = FieldMap::new("test");
        assert!(map.insert(FieldDef { name: "a".into(), bit_start: 0, bit_len: 16, kind: FieldKind::UInt(Endian::Big) }));
        // overlaps [0,16)
        assert!(!map.insert(FieldDef { name: "b".into(), bit_start: 8, bit_len: 8, kind: FieldKind::Bytes }));
        assert!(map.insert(FieldDef { name: "c".into(), bit_start: 16, bit_len: 8, kind: FieldKind::Bytes }));
        assert_eq!(map.fields.len(), 2);
        let undone = map.undo().unwrap();
        assert_eq!(undone.name, "c");
        assert_eq!(map.fields.len(), 1);
    }

    #[test]
    fn kaitai_output_has_expected_shape() {
        let mut map = FieldMap::new("myproto");
        map.insert(FieldDef { name: "magic".into(), bit_start: 0, bit_len: 8, kind: FieldKind::UInt(Endian::Big) });
        map.insert(FieldDef { name: "counter".into(), bit_start: 16, bit_len: 32, kind: FieldKind::UInt(Endian::Big) });
        let ksy = to_kaitai(&map);
        assert!(ksy.contains("id: myproto"));
        assert!(ksy.contains("id: magic"));
        assert!(ksy.contains("type: u1"));
        assert!(ksy.contains("id: counter"));
        assert!(ksy.contains("type: u4be"));
        assert!(ksy.contains("unknown0")); // the untagged gap byte at bit 8..16
    }

    #[test]
    fn lua_output_has_expected_shape() {
        let mut map = FieldMap::new("myproto");
        map.insert(FieldDef { name: "flag_x".into(), bit_start: 0, bit_len: 1, kind: FieldKind::Flag });
        map.insert(FieldDef { name: "session".into(), bit_start: 8, bit_len: 32, kind: FieldKind::UInt(Endian::Big) });
        let mut meta = PacketMeta::empty();
        meta.ip_proto = Some(17);
        meta.dport = Some(5000);
        let lua = to_lua(&map, &meta);
        assert!(lua.contains("Proto(\"myproto\""));
        assert!(lua.contains("ProtoField.bool"));
        assert!(lua.contains("0x80")); // flag_x is bit 0 of its byte
        assert!(lua.contains("ProtoField.uint32"));
        assert!(lua.contains("DissectorTable.get(\"udp.port\"):add(5000, myproto)"));
    }
}

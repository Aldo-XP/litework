//! A deliberately scoped interpreter for Kaitai Struct (`.ksy`) definitions.
//!
//! Rather than porting Wireshark's ~3,000 GPL-licensed C dissectors (which
//! would also force a GPL binary and reintroduce the C-dependency problem
//! this project avoids), litework executes the open Kaitai Struct format
//! catalog directly — plain YAML, permissively licensed, and a format
//! litework already speaks (`annotate::to_kaitai` exports to it).
//!
//! This covers flat, fixed-layout protocols — the common case for the
//! byte/bit reverse-engineering workflow this tool targets — not the full
//! Kaitai expression/type system. Unsupported constructs (`switch-on`,
//! cross-file `imports`, `instances`, `process`, arithmetic expressions
//! beyond a bare literal or field reference) simply stop interpretation at
//! that point, keeping whatever was already parsed — never panics, never
//! silently misinterprets.

use crate::annotate::{extract_uint, Endian, FieldDef, FieldKind};
use std::collections::HashMap;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone)]
enum TypeSpec {
    UInt(usize, Endian),
    Int(usize, Endian),
    /// Sub-byte bitfield, always MSB-first (Kaitai has no bitfield endian).
    Bit(usize),
    Str,
    /// No `type:` given — sized raw bytes.
    Bytes,
    /// A reference to a locally-defined entry in `types:`.
    Named(String),
}

#[derive(Debug, Clone)]
enum SizeSpec {
    Literal(usize),
    /// A previously-parsed sibling field's integer value.
    Ref(String),
    Eos,
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone)]
struct Cond {
    field: String,
    op: CmpOp,
    val: i64,
}

#[derive(Debug, Clone)]
enum RepeatSpec {
    Expr(SizeSpec),
    Eos,
}

#[derive(Debug, Clone)]
struct Attr {
    id: String,
    type_spec: TypeSpec,
    size: Option<SizeSpec>,
    repeat: Option<RepeatSpec>,
    if_cond: Option<Cond>,
    enum_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct TypeDef {
    seq: Vec<Attr>,
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub id: String,
    root: Vec<Attr>,
    types: HashMap<String, TypeDef>,
    enums: HashMap<String, HashMap<i64, String>>,
}

// ---------------------------------------------------------------- parsing

pub fn parse(yaml_src: &str) -> Result<Spec, String> {
    let docs = YamlLoader::load_from_str(yaml_src).map_err(|e| format!("yaml error: {e}"))?;
    let doc = docs.first().ok_or("empty yaml document")?;
    let id = doc["meta"]["id"].as_str().unwrap_or("proto").to_string();
    let default_endian = match doc["meta"]["endian"].as_str() {
        Some("le") => Endian::Little,
        _ => Endian::Big,
    };

    let mut types = HashMap::new();
    if let Some(h) = doc["types"].as_hash() {
        for (k, v) in h {
            if let Some(name) = k.as_str() {
                types.insert(name.to_string(), TypeDef { seq: parse_seq(&v["seq"], default_endian) });
            }
        }
    }

    let mut enums = HashMap::new();
    if let Some(h) = doc["enums"].as_hash() {
        for (k, v) in h {
            let Some(name) = k.as_str() else { continue };
            let Some(vh) = v.as_hash() else { continue };
            let mut map = HashMap::new();
            for (ek, ev) in vh {
                if let (Some(n), Some(s)) = (ek.as_i64(), ev.as_str()) {
                    map.insert(n, s.to_string());
                }
            }
            enums.insert(name.to_string(), map);
        }
    }

    let root = parse_seq(&doc["seq"], default_endian);
    Ok(Spec { id, root, types, enums })
}

fn parse_seq(v: &Yaml, default_endian: Endian) -> Vec<Attr> {
    v.as_vec().map(|arr| arr.iter().filter_map(|item| parse_attr(item, default_endian)).collect()).unwrap_or_default()
}

fn parse_attr(v: &Yaml, default_endian: Endian) -> Option<Attr> {
    let id = v["id"].as_str()?.to_string();
    let type_spec = parse_type_spec(v["type"].as_str(), default_endian);
    let size = if v["size-eos"].as_bool() == Some(true) { Some(SizeSpec::Eos) } else { parse_size(&v["size"]) };
    let repeat = parse_repeat(v);
    let if_cond = v["if"].as_str().and_then(parse_cond);
    let enum_name = v["enum"].as_str().map(|s| s.to_string());
    Some(Attr { id, type_spec, size, repeat, if_cond, enum_name })
}

fn parse_type_spec(type_str: Option<&str>, default_endian: Endian) -> TypeSpec {
    let Some(t) = type_str else { return TypeSpec::Bytes };
    if let Some(rest) = t.strip_prefix('b') {
        if let Ok(bits) = rest.parse::<usize>() {
            return TypeSpec::Bit(bits);
        }
    }
    for (prefix, signed) in [("u", false), ("s", true)] {
        if let Some(rest) = t.strip_prefix(prefix) {
            let (num, endian) = if let Some(n) = rest.strip_suffix("le") {
                (n, Endian::Little)
            } else if let Some(n) = rest.strip_suffix("be") {
                (n, Endian::Big)
            } else {
                (rest, default_endian)
            };
            if let Ok(bytes) = num.parse::<usize>() {
                return if signed { TypeSpec::Int(bytes, endian) } else { TypeSpec::UInt(bytes, endian) };
            }
        }
    }
    match t {
        "str" | "strz" => TypeSpec::Str,
        other => TypeSpec::Named(other.to_string()),
    }
}

fn parse_size(v: &Yaml) -> Option<SizeSpec> {
    match v {
        Yaml::Integer(n) if *n >= 0 => Some(SizeSpec::Literal(*n as usize)),
        Yaml::String(s) => Some(SizeSpec::Ref(s.clone())),
        _ => None,
    }
}

fn parse_repeat(v: &Yaml) -> Option<RepeatSpec> {
    match v["repeat"].as_str() {
        Some("expr") => parse_size(&v["repeat-expr"]).map(RepeatSpec::Expr),
        Some("eos") => Some(RepeatSpec::Eos),
        _ => None,
    }
}

fn parse_int_literal(s: &str) -> Option<i64> {
    if let Some(hex) = s.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_cond(s: &str) -> Option<Cond> {
    for (op_str, op) in [
        ("==", CmpOp::Eq),
        ("!=", CmpOp::Ne),
        (">=", CmpOp::Ge),
        ("<=", CmpOp::Le),
        (">", CmpOp::Gt),
        ("<", CmpOp::Lt),
    ] {
        if let Some((field, val)) = s.split_once(op_str) {
            let val = parse_int_literal(val.trim())?;
            return Some(Cond { field: field.trim().to_string(), op, val });
        }
    }
    None
}

// ------------------------------------------------------------ interpreting

const MAX_REPEAT: usize = 10_000;

struct Ctx<'a> {
    spec: &'a Spec,
    /// Last-seen integer value per *bare* field id (not name-qualified), for
    /// `size`/`repeat-expr`/`if` references — matches Kaitai's own scoping
    /// (an expression can only see already-parsed sibling fields).
    values: HashMap<String, i64>,
    fields: Vec<FieldDef>,
}

fn qualify(prefix: &str, id: &str) -> String {
    if prefix.is_empty() {
        id.to_string()
    } else {
        format!("{prefix}.{id}")
    }
}

impl Ctx<'_> {
    fn resolve_size(&self, spec: &SizeSpec, data_len: usize, cursor_bit: usize) -> Option<usize> {
        match spec {
            SizeSpec::Literal(n) => Some(*n),
            SizeSpec::Ref(name) => self.values.get(name).map(|v| (*v).max(0) as usize),
            SizeSpec::Eos => Some(data_len.saturating_sub(cursor_bit / 8)),
        }
    }

    fn cond_ok(&self, cond: &Option<Cond>) -> bool {
        let Some(c) = cond else { return true };
        let Some(v) = self.values.get(&c.field) else { return true };
        match c.op {
            CmpOp::Eq => *v == c.val,
            CmpOp::Ne => *v != c.val,
            CmpOp::Gt => *v > c.val,
            CmpOp::Lt => *v < c.val,
            CmpOp::Ge => *v >= c.val,
            CmpOp::Le => *v <= c.val,
        }
    }

    fn run_seq(&mut self, seq: &[Attr], data: &[u8], mut cursor_bit: usize, prefix: &str) -> usize {
        for attr in seq {
            if !self.cond_ok(&attr.if_cond) {
                continue;
            }
            match &attr.repeat {
                None => match self.run_attr(attr, data, cursor_bit, &qualify(prefix, &attr.id)) {
                    Some(next) => cursor_bit = next,
                    None => return cursor_bit,
                },
                Some(RepeatSpec::Expr(sz)) => {
                    let Some(n) = self.resolve_size(sz, data.len(), cursor_bit) else { return cursor_bit };
                    for i in 0..n.min(MAX_REPEAT) {
                        let name = format!("{}[{i}]", qualify(prefix, &attr.id));
                        match self.run_attr(attr, data, cursor_bit, &name) {
                            Some(next) => cursor_bit = next,
                            None => return cursor_bit,
                        }
                    }
                }
                Some(RepeatSpec::Eos) => {
                    for i in 0..MAX_REPEAT {
                        if cursor_bit / 8 >= data.len() {
                            break;
                        }
                        let name = format!("{}[{i}]", qualify(prefix, &attr.id));
                        match self.run_attr(attr, data, cursor_bit, &name) {
                            Some(next) if next > cursor_bit => cursor_bit = next,
                            _ => break, // no progress or failure: stop rather than loop forever
                        }
                    }
                }
            }
        }
        cursor_bit
    }

    /// Parse one occurrence of `attr` at `cursor_bit`; `None` means it
    /// couldn't be resolved (e.g. an unresolvable size reference) —
    /// interpretation of the enclosing seq stops there.
    fn run_attr(&mut self, attr: &Attr, data: &[u8], cursor_bit: usize, name: &str) -> Option<usize> {
        match &attr.type_spec {
            TypeSpec::UInt(bytes, endian) => {
                self.push_scalar(attr, name, cursor_bit, bytes * 8, FieldKind::UInt(*endian), data);
                Some(cursor_bit + bytes * 8)
            }
            TypeSpec::Int(bytes, endian) => {
                self.push_scalar(attr, name, cursor_bit, bytes * 8, FieldKind::Int(*endian), data);
                Some(cursor_bit + bytes * 8)
            }
            TypeSpec::Bit(bits) => {
                self.push_scalar(attr, name, cursor_bit, *bits, FieldKind::UInt(Endian::Big), data);
                Some(cursor_bit + bits)
            }
            TypeSpec::Str => {
                let byte_len = self.resolve_size(attr.size.as_ref()?, data.len(), cursor_bit)?;
                self.fields.push(FieldDef {
                    name: name.to_string(),
                    bit_start: cursor_bit,
                    bit_len: byte_len * 8,
                    kind: FieldKind::Ascii,
                });
                Some(cursor_bit + byte_len * 8)
            }
            TypeSpec::Bytes => {
                let byte_len = self.resolve_size(attr.size.as_ref()?, data.len(), cursor_bit)?;
                self.fields.push(FieldDef {
                    name: name.to_string(),
                    bit_start: cursor_bit,
                    bit_len: byte_len * 8,
                    kind: FieldKind::Bytes,
                });
                Some(cursor_bit + byte_len * 8)
            }
            TypeSpec::Named(type_name) => {
                let seq = self.spec.types.get(type_name)?.seq.clone();
                Some(self.run_seq(&seq, data, cursor_bit, name))
            }
        }
    }

    fn push_scalar(&mut self, attr: &Attr, name: &str, bit_start: usize, bit_len: usize, kind: FieldKind, data: &[u8]) {
        let endian = match kind {
            FieldKind::UInt(e) | FieldKind::Int(e) => e,
            _ => Endian::Big,
        };
        let raw = extract_uint(data, bit_start, bit_len, endian);
        if let Some(v) = raw {
            self.values.insert(attr.id.clone(), v as i64);
        }
        let mut display_name = name.to_string();
        if let (Some(en), Some(v)) = (&attr.enum_name, raw) {
            if let Some(label) = self.spec.enums.get(en).and_then(|m| m.get(&(v as i64))) {
                display_name = format!("{name} ({label})");
            }
        }
        self.fields.push(FieldDef { name: display_name, bit_start, bit_len, kind });
    }
}

/// Interpret `spec` against `data`, producing the same `FieldDef`s manual
/// tagging would — so every renderer that already knows how to display one
/// (BYTES tab grid/info panel, PACKETS detail pane) needs no Kaitai-specific
/// code.
pub fn interpret(spec: &Spec, data: &[u8]) -> Vec<FieldDef> {
    let mut ctx = Ctx { spec, values: HashMap::new(), fields: Vec::new() };
    ctx.run_seq(&spec.root, data, 0, "");
    ctx.fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annotate::decode;

    #[test]
    fn parses_and_interprets_flat_fields() {
        let ksy = r#"
meta:
  id: myproto
seq:
  - id: magic
    type: u1
  - id: counter
    type: u4be
  - id: name
    type: str
    size: 4
    encoding: ASCII
"#;
        let spec = parse(ksy).unwrap();
        let data = [0xAB, 0x00, 0x00, 0x03, 0xE8, b'N', b'O', b'D', b'E'];
        let fields = interpret(&spec, &data);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "magic");
        assert_eq!(fields[0].bit_start, 0);
        assert_eq!(fields[0].bit_len, 8);
        assert_eq!(decode(&fields[0].kind, fields[0].bit_start, fields[0].bit_len, &data), "171 (0xab)");
        assert_eq!(fields[1].name, "counter");
        assert_eq!(fields[1].bit_start, 8);
        assert_eq!(decode(&fields[1].kind, fields[1].bit_start, fields[1].bit_len, &data), "1000 (0x3e8)");
        assert_eq!(fields[2].name, "name");
        assert_eq!(decode(&fields[2].kind, fields[2].bit_start, fields[2].bit_len, &data), "NODE");
    }

    #[test]
    fn bitfield_and_little_endian() {
        let ksy = r#"
meta:
  id: bits
seq:
  - id: flag
    type: b1
  - id: reserved
    type: b7
  - id: val
    type: u2le
"#;
        let spec = parse(ksy).unwrap();
        let data = [0b1000_0000u8, 0x34, 0x12];
        let fields = interpret(&spec, &data);
        assert_eq!(fields[0].bit_len, 1);
        assert_eq!(decode(&fields[0].kind, fields[0].bit_start, fields[0].bit_len, &data), "1 (0x1)");
        assert_eq!(fields[1].bit_start, 1);
        assert_eq!(fields[1].bit_len, 7);
        assert_eq!(fields[2].bit_start, 8);
        assert_eq!(decode(&fields[2].kind, fields[2].bit_start, fields[2].bit_len, &data), "4660 (0x1234)");
    }

    #[test]
    fn repeat_expr_array() {
        let ksy = r#"
meta:
  id: arr
seq:
  - id: count
    type: u1
  - id: items
    type: u2be
    repeat: expr
    repeat-expr: count
"#;
        let spec = parse(ksy).unwrap();
        let data = [0x03u8, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C];
        let fields = interpret(&spec, &data);
        assert_eq!(fields.len(), 4); // count + 3 items
        assert_eq!(fields[1].name, "items[0]");
        assert_eq!(decode(&fields[1].kind, fields[1].bit_start, fields[1].bit_len, &data), "10 (0xa)");
        assert_eq!(fields[3].name, "items[2]");
        assert_eq!(decode(&fields[3].kind, fields[3].bit_start, fields[3].bit_len, &data), "12 (0xc)");
    }

    #[test]
    fn nested_type_and_enum() {
        let ksy = r#"
meta:
  id: nested
seq:
  - id: proto
    type: u1
    enum: ip_proto
  - id: hdr
    type: sub
enums:
  ip_proto:
    6: tcp
    17: udp
types:
  sub:
    seq:
      - id: a
        type: u1
      - id: b
        type: u1
"#;
        let spec = parse(ksy).unwrap();
        let data = [6u8, 0xAA, 0xBB];
        let fields = interpret(&spec, &data);
        assert_eq!(fields[0].name, "proto (tcp)");
        assert_eq!(fields[1].name, "hdr.a");
        assert_eq!(fields[2].name, "hdr.b");
        assert_eq!(decode(&fields[2].kind, fields[2].bit_start, fields[2].bit_len, &data), "187 (0xbb)");
    }

    #[test]
    fn unsupported_construct_stops_gracefully_without_panicking() {
        let ksy = r#"
meta:
  id: sw
seq:
  - id: kind
    type: u1
  - id: body
    type:
      switch-on: kind
      cases:
        1: type_a
        2: type_b
  - id: never_reached
    type: u1
"#;
        // `type:` here is a mapping, not a string — parse_type_spec sees
        // `as_str()` return None and falls back to Bytes with no size,
        // which is unresolvable, so interpretation stops after `kind`.
        let spec = parse(ksy).unwrap();
        let data = [1u8, 2, 3];
        let fields = interpret(&spec, &data);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "kind");
    }

    #[test]
    fn round_trip_through_own_kaitai_export() {
        use crate::annotate::{FieldMap};
        let mut map = FieldMap::new("roundtrip");
        map.insert(FieldDef { name: "a".into(), bit_start: 0, bit_len: 8, kind: FieldKind::UInt(Endian::Big) });
        map.insert(FieldDef { name: "b".into(), bit_start: 8, bit_len: 32, kind: FieldKind::UInt(Endian::Little) });
        let ksy_text = crate::annotate::to_kaitai(&map);

        let spec = parse(&ksy_text).expect("litework's own kaitai export must parse back");
        let data = [0x42u8, 0x01, 0x02, 0x03, 0x04];
        let fields = interpret(&spec, &data);
        assert_eq!(fields.len(), 2);
        for (original, reparsed) in map.sorted().iter().zip(fields.iter()) {
            assert_eq!(original.bit_start, reparsed.bit_start);
            assert_eq!(original.bit_len, reparsed.bit_len);
            let expected = decode(&original.kind, original.bit_start, original.bit_len, &data);
            let actual = decode(&reparsed.kind, reparsed.bit_start, reparsed.bit_len, &data);
            assert_eq!(expected, actual);
        }
    }
}

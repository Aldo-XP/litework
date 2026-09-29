# lwz

Format-aware, lossless compression for packet captures. Built for NDJSON files
of DVB-S2 baseband-frame records, and also handles legacy pcap:

```json
{"timestamp":1787035353.906961,"bbframe":"FgAAABnI4wAAZ8AtZZQA...","metadata":{"ma_hdr":"bQ==","udp_dst":12}}
```

```
lwz pack frames.ndjson                    # -> frames.ndjson.lwz
lwz pack frames.ndjson --stats --verify   # column breakdown + in-memory round-trip check
lwz pack frames.ndjson --strict           # refuse malformed lines instead of keeping them verbatim
lwz unpack frames.ndjson.lwz              # -> frames.ndjson, byte-identical
```

## What it does

General-purpose compressors see one undifferentiated byte stream. `lwz` takes
each record apart first, so every piece lands next to things that look like it:

| Step | Effect |
|---|---|
| base64 → bytes | −25% before anything else happens |
| timestamp → delta at its own precision | ~7 digits of entropy → 1–2 bytes |
| metadata object → text column | identical objects collapse to nothing |
| BBHEADER fields → 6 columns | MATYPE/UPL/DFL/SYNC/SYNCD/CRC8 each repeat |
| GSE walk | 2-byte headers + 9-byte prefixes in their own columns |
| IPv4/TCP/UDP modelling | per-flow prediction: IDs, seq/ack, TTL, lengths become mostly zeros; checksums are **recomputed**, only the residual is stored (0 when valid, a constant when a middlebox mangled it) |
| payload routing | grouped by protocol class, then by flow, so repeated templates sit together |
| LZMA per column | every column compressed independently, in parallel |

Everything is verified as it goes: timestamps and base64 are re-rendered and
compared; a line that would not reproduce exactly is stored verbatim and
counted in the report. Frames with an invalid BBHEADER are stored as opaque
bytes. The decoder is the exact inverse — `--verify` proves it per run.

## Validation report

```
jsonl  260.2 MB → 112.1 MB  (2.3x smaller)  2 blocks  13.9s
lines: 60000 total, 59871 modelled, 129 stored verbatim (shape 61, timestamp 29, base64 39)
gse: 1445750 packets (916073 ipv4, 529677 opaque), 1.6 MB padding, 0 B tail
```

`--stats` adds a per-column table so you can see which bytes still resist
(typically encrypted or random payload — nothing compresses that).

## Limits

- Ratio depends entirely on payload entropy. Headers shrink 10–50x; encrypted or
  already-compressed payload stays ~1:1. Expect 2–5x better than `xz -9` on
  header-heavy traffic, close to parity on pure ciphertext.
- pcapng input is not supported (convert with `editcap -F pcap`).
- Memory ≈ 3 × `--block-mb` (default 128 MB) per in-flight block.

## Archive format

`LWZ1`, version byte, kind byte, then self-contained blocks
(`u64 items, u32 ncols, ncols × {u32 key, u8 codec, u64 raw, u64 packed, bytes}`),
terminated by `items = 0`. Each block resets its flow tables, so a damaged
archive loses at most one block. Pure Rust, no C dependencies; builds as a
fully static binary.

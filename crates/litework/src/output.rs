//! Report rendering for the CLI commands (human tables + JSON).

use anyhow::Result;
use litework_core::query::{run_query, Expr};
use litework_core::types::{fmt_bytes, fmt_mac, fmt_net_addr, fmt_ts, ProtoKey};
use litework_core::{CaptureIndex, PcapFile};
use serde_json::json;

const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

fn spark(counts: &[u64], width: usize) -> String {
    if counts.is_empty() || width == 0 {
        return String::new();
    }
    // Downsample buckets to `width` columns by summing.
    let mut cols = vec![0u64; width];
    for (i, &c) in counts.iter().enumerate() {
        cols[i * width / counts.len()] += c;
    }
    let max = cols.iter().copied().max().unwrap_or(0).max(1);
    cols.iter()
        .map(|&c| {
            if c == 0 {
                ' '
            } else {
                BLOCKS[(((c * 7).div_ceil(max)) as usize).min(7)]
            }
        })
        .collect()
}



pub fn stats_report(file: &PcapFile, index: &CaptureIndex, top: usize) -> Result<()> {
    let s = &index.stats;
    println!(
        "{}  {}  {} packets  {}",
        file.path.display(),
        fmt_bytes(file.len()),
        s.packets,
        fmt_bytes(s.bytes)
    );
    if s.first_ts != u64::MAX {
        let dur = (s.last_ts.saturating_sub(s.first_ts)) as f64 / 1e9;
        println!(
            "time    {} → {}  ({:.1}s)",
            fmt_ts(s.first_ts),
            fmt_ts(s.last_ts),
            dur
        );
    }
    println!(
        "index   {} row groups, {} in {} ms{}",
        index.groups.len(),
        if index.loaded_from_sidecar { "loaded from sidecar" } else { "built" },
        index.build_millis,
        if index.truncated { "  [truncated capture]" } else { "" }
    );

    if let Some((a, b)) = s.hist.span() {
        let w = s.hist.width_nanos() as f64 / 1e9;
        println!("\ntraffic ({}s/col)", trim_f(w * (b - a + 1) as f64 / 72.0));
        println!("  {}", spark(&s.hist.counts()[a..=b], 72));
    }

    println!("\nprotocols");
    for (k, pkts, bytes) in index.stats.top_protos().into_iter().take(top) {
        let pct = pkts as f64 * 100.0 / s.packets.max(1) as f64;
        let bar_len = (pct / 100.0 * 30.0).round() as usize;
        println!(
            "  {:<12} {:>6.1}%  {:>10} pkts  {:>9}  {}",
            k.name(),
            pct,
            pkts,
            fmt_bytes(bytes),
            "▇".repeat(bar_len.max(if pkts > 0 { 1 } else { 0 }))
        );
    }

    println!("\ntop MACs (of {})", index.dict.len());
    for (id, m) in index.stats.top_macs().into_iter().take(top) {
        let protos: Vec<String> = m.protos.iter().map(|p| p.name()).collect();
        println!(
            "  {}  {:>10} pkts  {:>9}  {{{}}}",
            fmt_mac(&index.dict.get(id)),
            m.pkts,
            fmt_bytes(m.bytes),
            protos.join(",")
        );
    }

    let ports = index.stats.top_ports(top);
    if !ports.is_empty() {
        println!("\ntop ports");
        for (p, c) in ports {
            println!("  {:<6} {:>10} pkts  {}", p, c, crate::tui::packets::service_hint(p));
        }
    }
    Ok(())
}

fn trim_f(v: f64) -> String {
    if v >= 10.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}


pub fn stats_json(file: &PcapFile, index: &CaptureIndex, top: usize) -> Result<()> {
    let s = &index.stats;
    let protos: Vec<_> = index.stats.top_protos()
        .into_iter()
        .map(|(k, p, b)| json!({"proto": k.name(), "packets": p, "bytes": b}))
        .collect();
    let macs: Vec<_> = index.stats.top_macs()
        .into_iter()
        .take(top)
        .map(|(id, m)| {
            json!({
                "mac": fmt_mac(&index.dict.get(id)),
                "packets": m.pkts,
                "bytes": m.bytes,
                "protocols": m.protos.iter().map(|p| p.name()).collect::<Vec<_>>(),
                "first_ts_nanos": m.first_ts,
                "last_ts_nanos": m.last_ts,
            })
        })
        .collect();
    let ports: Vec<_> = index.stats.top_ports(top)
        .into_iter()
        .map(|(p, c)| json!({"port": p, "packets": c}))
        .collect();
    let (ha, hb) = s.hist.span().unwrap_or((0, 0));
    let doc = json!({
        "file": file.path.display().to_string(),
        "file_bytes": file.len(),
        "packets": s.packets,
        "bytes": s.bytes,
        "first_ts_nanos": if s.first_ts == u64::MAX { 0 } else { s.first_ts },
        "last_ts_nanos": s.last_ts,
        "truncated": index.truncated,
        "row_groups": index.groups.len(),
        "build_millis": index.build_millis,
        "unique_macs": index.dict.len(),
        "protocols": protos,
        "top_macs": macs,
        "top_ports": ports,
        "histogram": {
            "bucket_nanos": s.hist.width_nanos(),
            "origin_nanos": s.hist.origin_nanos(),
            "first_bucket": ha,
            "counts": &s.hist.counts()[ha..=hb.max(ha)],
        },
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

/// One packet as a display line (shared by query output and live streaming).
pub fn packet_line(rec: &litework_core::types::PacketRecord, meta: &litework_core::types::PacketMeta, json: bool) -> String {
    let (src, dst) = fmt_net_addr(&meta.net);
    if json {
        json!({
            "ts_nanos": rec.ts_nanos,
            "len": rec.origlen,
            "mac_src": meta.has_eth.then(|| fmt_mac(&meta.mac_src)),
            "mac_dst": meta.has_eth.then(|| fmt_mac(&meta.mac_dst)),
            "ip_src": (src != "-").then_some(&src),
            "ip_dst": (dst != "-").then_some(&dst),
            "proto": ProtoKey::of(meta).name(),
            "sport": meta.sport,
            "dport": meta.dport,
            "vlan": meta.vlan,
        })
        .to_string()
    } else {
        let ports = match (meta.sport, meta.dport) {
            (Some(s), Some(d)) => format!("{s}→{d}"),
            _ => "-".into(),
        };
        format!(
            "{:<23} {:<17} {:<17} {:<39} {:>11} {:<8} {:>6}",
            fmt_ts(rec.ts_nanos),
            if meta.has_eth { fmt_mac(&meta.mac_src) } else { "-".into() },
            if meta.has_eth { fmt_mac(&meta.mac_dst) } else { "-".into() },
            format!("{src} → {dst}"),
            ports,
            ProtoKey::of(meta).name(),
            rec.origlen,
        )
    }
}

pub fn query_report(
    file: &PcapFile,
    index: &CaptureIndex,
    expr: &Expr,
    json: bool,
    limit: u64,
    count_only: bool,
) -> Result<()> {
    let mut shown = 0u64;
    if !json && !count_only {
        println!(
            "{:<23} {:<17} {:<17} {:<39} {:>7} {:<8} {:>6}",
            "time", "mac_src", "mac_dst", "ip_src → ip_dst", "ports", "proto", "len"
        );
    }
    let run = run_query(file, index, expr, |rec, meta| {
        if count_only {
            return true;
        }
        shown += 1;
        let (src, dst) = fmt_net_addr(&meta.net);
        if json {
            println!(
                "{}",
                json!({
                    "ts_nanos": rec.ts_nanos,
                    "offset": rec.data_offset,
                    "caplen": rec.caplen,
                    "len": rec.origlen,
                    "mac_src": meta.has_eth.then(|| fmt_mac(&meta.mac_src)),
                    "mac_dst": meta.has_eth.then(|| fmt_mac(&meta.mac_dst)),
                    "ip_src": (src != "-").then_some(&src),
                    "ip_dst": (dst != "-").then_some(&dst),
                    "proto": ProtoKey::of(meta).name(),
                    "sport": meta.sport,
                    "dport": meta.dport,
                    "vlan": meta.vlan,
                })
            );
        } else {
            let ports = match (meta.sport, meta.dport) {
                (Some(s), Some(d)) => format!("{s}→{d}"),
                _ => "-".into(),
            };
            println!(
                "{:<23} {:<17} {:<17} {:<39} {:>7} {:<8} {:>6}",
                fmt_ts(rec.ts_nanos),
                if meta.has_eth { fmt_mac(&meta.mac_src) } else { "-".into() },
                if meta.has_eth { fmt_mac(&meta.mac_dst) } else { "-".into() },
                format!("{src} → {dst}"),
                ports,
                ProtoKey::of(meta).name(),
                rec.origlen,
            );
        }
        limit == 0 || shown < limit
    })?;
    let pruned_pct = if run.groups_total > 0 {
        100.0 - run.groups_scanned as f64 * 100.0 / run.groups_total as f64
    } else {
        0.0
    };
    eprintln!(
        "{} matches ({} shown) — scanned {}/{} row groups ({:.0}% pruned), {} packets",
        run.matched,
        if count_only { 0 } else { shown },
        run.groups_scanned,
        run.groups_total,
        pruned_pct,
        run.packets_scanned
    );
    Ok(())
}

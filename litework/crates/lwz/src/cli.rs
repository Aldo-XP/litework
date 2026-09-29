//! Command implementations for the `lwz` binary.

use anyhow::{bail, Context, Result};
use litework_pack::{self as pack, PackOptions, Reader, KIND_JSONL, KIND_PCAP};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn fmt_bytes(n: u64) -> String {
    let f = n as f64;
    if f >= 1e9 {
        format!("{:.2} GB", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MB", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.1} KB", f / 1e3)
    } else {
        format!("{n} B")
    }
}

fn detect_kind(head: &[u8]) -> Result<u8> {
    if head.len() >= 4 {
        let m = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        if matches!(m, 0xa1b2_c3d4 | 0xa1b2_3c4d | 0xd4c3_b2a1 | 0x4d3c_b2a1) {
            return Ok(KIND_PCAP);
        }
        if m == 0x0a0d_0d0a {
            bail!("pcapng input is not supported yet — convert first: litework export in.pcapng out.pcap");
        }
    }
    let trimmed = head.iter().position(|b| !b.is_ascii_whitespace()).map(|i| &head[i..]);
    if let Some(t) = trimmed {
        if t.starts_with(b"{") {
            return Ok(KIND_JSONL);
        }
    }
    bail!("cannot tell what this is: not a pcap and not JSON lines")
}

#[allow(clippy::too_many_arguments)]
pub fn pack(
    file: &Path,
    out: Option<&Path>,
    level: u32,
    block_mb: usize,
    threads: Option<usize>,
    stats: bool,
    verify: bool,
    strict: bool,
) -> Result<()> {
    if !(1..=9).contains(&level) {
        bail!("--level must be 1-9");
    }
    let stdin_mode = file == Path::new("-");
    let out_path: Option<PathBuf> = match (out, stdin_mode) {
        (Some(o), _) if o == Path::new("-") => None,
        (Some(o), _) => Some(o.to_path_buf()),
        (None, true) => None,
        (None, false) => {
            let mut p = file.as_os_str().to_owned();
            p.push(".lwz");
            Some(PathBuf::from(p))
        }
    };
    if verify && (stdin_mode || out_path.is_none()) {
        bail!("--verify needs a regular input file and output file");
    }
    let mut opts = PackOptions {
        level,
        block_bytes: block_mb.max(1) << 20,
        ..PackOptions::default()
    };
    if let Some(t) = threads {
        opts.threads = t.max(1);
    }

    // Input: peek the first bytes to choose the decoder.
    let mut input: Box<dyn Read> = if stdin_mode {
        Box::new(io::stdin().lock())
    } else {
        Box::new(File::open(file).with_context(|| format!("open {}", file.display()))?)
    };
    let in_size = if stdin_mode { None } else { std::fs::metadata(file).ok().map(|m| m.len()) };
    let mut head = vec![0u8; 64];
    let mut got = 0;
    while got < head.len() {
        let n = input.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    head.truncate(got);
    let kind = detect_kind(&head)?;
    let reader = BufReader::with_capacity(1 << 20, io::Cursor::new(head).chain(input));

    let output: Box<dyn Write + Send> = match &out_path {
        Some(p) => Box::new(BufWriter::with_capacity(
            1 << 20,
            File::create(p).with_context(|| format!("create {}", p.display()))?,
        )),
        None => Box::new(BufWriter::new(io::stdout())),
    };

    let t0 = Instant::now();
    let quiet = out_path.is_none();
    let mut last = Instant::now();
    let mut progress = |consumed: u64, items: u64| {
        if quiet || last.elapsed().as_millis() < 500 {
            return;
        }
        last = Instant::now();
        let pct = in_size
            .map(|s| format!(" {:3.0}%", consumed as f64 * 100.0 / s.max(1) as f64))
            .unwrap_or_default();
        eprint!(
            "\r  packing… {}{}  {} items  {:.0} MB/s   ",
            fmt_bytes(consumed),
            pct,
            items,
            consumed as f64 / 1e6 / t0.elapsed().as_secs_f64().max(1e-3)
        );
        let _ = io::stderr().flush();
    };
    let (w, report) = match kind {
        KIND_PCAP => pack::pcap::pack(reader, output, &opts, Some(&mut progress)).map(|w| (w, None)),
        _ => pack::jsonl::pack(reader, output, &opts, strict, Some(&mut progress)).map(|(w, r)| (w, Some(r))),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let (mut out_w, summary) = w.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    out_w.flush()?;
    drop(out_w);
    let col_stats = summary.stats;
    let blocks = summary.blocks;
    if !quiet {
        eprint!("\r{:70}\r", "");
    }

    let raw: u64 = col_stats.values().map(|s| s.raw).sum();
    let comp: u64 = col_stats.values().map(|s| s.comp).sum();
    let input_bytes = in_size.unwrap_or(raw);
    let secs = t0.elapsed().as_secs_f64();
    let out_size = out_path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(comp);
    if !quiet {
        eprintln!(
            "{}  {} → {}  ({:.1}x smaller, {:.1}% of input)  {} blocks  {:.1}s  {:.0} MB/s",
            match kind {
                KIND_PCAP => "pcap",
                _ => "jsonl",
            },
            fmt_bytes(input_bytes),
            fmt_bytes(out_size),
            input_bytes as f64 / out_size.max(1) as f64,
            out_size as f64 * 100.0 / input_bytes.max(1) as f64,
            blocks,
            secs,
            input_bytes as f64 / 1e6 / secs.max(1e-3)
        );
    }
    if let Some(r) = &report {
        if !quiet {
            let mut line = format!("lines: {} total, {} modelled", r.lines, r.modelled);
            if r.rejected() > 0 {
                line.push_str(&format!(
                    ", {} stored verbatim (shape {}, timestamp {}, base64 {})",
                    r.rejected(),
                    r.rejected_shape,
                    r.rejected_timestamp,
                    r.rejected_base64
                ));
            }
            if r.frames_raw > 0 {
                line.push_str(&format!(", {} frames with bad BBHEADER", r.frames_raw));
            }
            eprintln!("{line}");
            eprintln!(
                "gse: {} packets ({} ipv4, {} opaque), {} padding, {} tail",
                r.gse_packets,
                r.gse_ipv4,
                r.gse_opaque,
                fmt_bytes(r.padding_bytes),
                fmt_bytes(r.tail_bytes)
            );
        }
    }
    if stats {
        let mut rows: Vec<(u32, u64, u64)> = col_stats.iter().map(|(k, s)| (*k, s.raw, s.comp)).collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.2));
        eprintln!("\n{:<34} {:>12} {:>12} {:>7} {:>7}", "column", "raw", "packed", "ratio", "share");
        for (k, r, c) in rows {
            eprintln!(
                "{:<34} {:>12} {:>12} {:>6.1}x {:>6.1}%",
                pack::col_name(k),
                fmt_bytes(r),
                fmt_bytes(c),
                r as f64 / c.max(1) as f64,
                c as f64 * 100.0 / comp.max(1) as f64
            );
        }
        eprintln!("{:<34} {:>12} {:>12} {:>6.1}x", "total", fmt_bytes(raw), fmt_bytes(comp), raw as f64 / comp.max(1) as f64);
    }
    if verify {
        let arc = out_path.as_ref().unwrap();
        let t1 = Instant::now();
        verify_archive(arc, file)?;
        eprintln!("verified: unpack reproduces {} byte-for-byte ({:.1}s)", file.display(), t1.elapsed().as_secs_f64());
    }
    Ok(())
}

/// Unpack `arc` and compare against `orig` without writing a file.
fn verify_archive(arc: &Path, orig: &Path) -> Result<()> {
    struct Cmp {
        f: BufReader<File>,
        pos: u64,
        mismatch: Option<u64>,
        buf: Vec<u8>,
    }
    impl Write for Cmp {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.mismatch.is_none() {
                self.buf.resize(b.len(), 0);
                let mut n = 0;
                while n < b.len() {
                    let k = self.f.read(&mut self.buf[n..])?;
                    if k == 0 {
                        break;
                    }
                    n += k;
                }
                if n < b.len() || self.buf[..n] != *b {
                    let off = self.buf[..n].iter().zip(b).position(|(x, y)| x != y).unwrap_or(n);
                    self.mismatch = Some(self.pos + off as u64);
                }
            }
            self.pos += b.len() as u64;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut cmp = Cmp {
        f: BufReader::with_capacity(1 << 20, File::open(orig)?),
        pos: 0,
        mismatch: None,
        buf: Vec::new(),
    };
    let rd = Reader::new(BufReader::with_capacity(1 << 20, File::open(arc)?)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let kind = rd.kind;
    match kind {
        KIND_PCAP => pack::pcap::unpack(rd, &mut cmp),
        _ => pack::jsonl::unpack(rd, &mut cmp),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(off) = cmp.mismatch {
        bail!("VERIFY FAILED: output differs from input at byte {off}");
    }
    let orig_len = cmp.f.seek(SeekFrom::End(0))?;
    if cmp.pos != orig_len {
        bail!("VERIFY FAILED: output is {} bytes, input is {orig_len}", cmp.pos);
    }
    Ok(())
}

pub fn unpack(file: &Path, out: Option<&Path>) -> Result<()> {
    let stdin_mode = file == Path::new("-");
    let out_path: Option<PathBuf> = match (out, stdin_mode) {
        (Some(o), _) if o == Path::new("-") => None,
        (Some(o), _) => Some(o.to_path_buf()),
        (None, true) => None,
        (None, false) => match file.extension() {
            Some(e) if e == "lwz" => Some(file.with_extension("")),
            _ => bail!("input doesn't end in .lwz; give -o <output>"),
        },
    };
    let input: Box<dyn Read> = if stdin_mode {
        Box::new(io::stdin().lock())
    } else {
        Box::new(File::open(file).with_context(|| format!("open {}", file.display()))?)
    };
    let rd = Reader::new(BufReader::with_capacity(1 << 20, input)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let output: Box<dyn Write> = match &out_path {
        Some(p) => {
            if p.exists() {
                bail!("{} already exists; remove it or use -o", p.display());
            }
            Box::new(BufWriter::with_capacity(1 << 20, File::create(p)?))
        }
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let t0 = Instant::now();
    let kind = rd.kind;
    let items = match kind {
        KIND_PCAP => pack::pcap::unpack(rd, output),
        _ => pack::jsonl::unpack(rd, output),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(p) = &out_path {
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        eprintln!(
            "{}  {} items  {}  {:.1}s",
            p.display(),
            items,
            fmt_bytes(size),
            t0.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

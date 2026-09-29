//! `litework capture`: live capture from an interface into a pcap file, with
//! the same filter language applied at capture time.

use crate::filterargs::FilterArgs;
use anyhow::{bail, Context, Result};
use litework_core::dissect::dissect;
use litework_core::types::{fmt_bytes, PacketRecord};
use litework_core::PcapWriter;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

fn install_sigint() {
    #[cfg(unix)]
    unsafe {
        extern "C" fn on_int(_: i32) {
            STOP.store(true, Ordering::SeqCst);
        }
        let handler = on_int as extern "C" fn(i32) as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    #[cfg(not(unix))]
    {
        let _ = ctrlc_fallback();
    }
}

#[cfg(not(unix))]
fn ctrlc_fallback() -> Result<()> {
    Ok(()) // windows console handler arrives with the Npcap work in M4
}

pub fn run(
    interface: Option<String>,
    write: Option<PathBuf>,
    json: bool,
    count: Option<u64>,
    seconds: Option<u64>,
    no_promisc: bool,
    filter: &FilterArgs,
) -> Result<()> {
    let Some(iface) = interface else {
        let names = litework_capture::interfaces();
        if names.is_empty() {
            bail!("no interfaces found (or unsupported platform)");
        }
        println!("available interfaces:");
        for n in names {
            println!("  {n}");
        }
        println!("\ncapture with: litework capture -i <name> -w out.pcap");
        return Ok(());
    };
    let expr = filter
        .compose_opt(None)?
        .map(|src| litework_core::parse_filter(&src))
        .transpose()?;

    let mut src = litework_capture::open(&iface, !no_promisc)
        .with_context(|| format!("opening {iface}"))?;
    let linktype = src.linktype();
    let mut writer = match &write {
        Some(out) => Some(PcapWriter::create(out, linktype)?),
        None => None,
    };
    install_sigint();

    let started = Instant::now();
    let deadline = seconds.map(|s| started + Duration::from_secs(s));
    let mut seen: u64 = 0;
    let mut kept: u64 = 0;
    let mut kept_bytes: u64 = 0;
    let mut last_print = Instant::now();
    let mut last_pkts = 0u64;
    match &write {
        Some(out) => eprintln!("capturing on {iface} → {} (Ctrl-C to stop)", out.display()),
        None => eprintln!("streaming from {iface} (Ctrl-C to stop)"),
    }
    let stdout = std::io::stdout();

    while !STOP.load(Ordering::SeqCst) {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        if let Some(c) = count {
            if kept >= c {
                break;
            }
        }
        let pkt = src.next()?;
        if let Some(p) = pkt {
            seen += 1;
            let rec = PacketRecord {
                ts_nanos: p.ts_nanos,
                record_offset: 0,
                data_offset: 0,
                caplen: p.data.len() as u32,
                origlen: p.origlen,
                linktype,
            };
            // Dissect when we need it: for the filter or for stream output.
            let meta = if expr.is_some() || writer.is_none() {
                Some(dissect(linktype, p.data))
            } else {
                None
            };
            let keep = match (&expr, &meta) {
                (Some(e), Some(m)) => e.matches(m, &rec, p.data),
                _ => true,
            };
            if keep {
                kept += 1;
                kept_bytes += p.data.len() as u64;
                match &mut writer {
                    Some(w) => w.write(p.ts_nanos, p.origlen, linktype, p.data)?,
                    None => {
                        let mut lock = stdout.lock();
                        if writeln!(
                            lock,
                            "{}",
                            crate::output::packet_line(&rec, meta.as_ref().unwrap(), json)
                        )
                        .is_err()
                        {
                            break; // stdout closed (piped to head etc.)
                        }
                    }
                }
            }
        }
        // Rate line only in write mode; streaming keeps stdout/stderr clean.
        if writer.is_some() && last_print.elapsed() >= Duration::from_secs(1) {
            let rate = kept - last_pkts;
            last_pkts = kept;
            last_print = Instant::now();
            eprint!(
                "\r{} pkts written ({}), {} seen, {} pkt/s   ",
                kept,
                fmt_bytes(kept_bytes),
                seen,
                rate
            );
            let _ = std::io::stderr().flush();
        }
    }
    if let Some(w) = writer {
        let (pkts, bytes, _) = w.finish()?;
        eprintln!(
            "\r\x1b[K{} packets written ({}), {} seen in {:.1}s → {}",
            pkts,
            fmt_bytes(bytes),
            seen,
            started.elapsed().as_secs_f64(),
            write.as_ref().unwrap().display()
        );
        if pkts > 0 {
            eprintln!("analyze with: litework {}", write.unwrap().display());
        }
    } else {
        eprintln!(
            "{} packets shown ({}), {} seen in {:.1}s",
            kept,
            fmt_bytes(kept_bytes),
            seen,
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

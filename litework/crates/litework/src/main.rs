//! LiteWork CLI: TUI, stats, query, export, index, live capture.

mod capture_cmd;
mod filterargs;
mod output;
mod tui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use filterargs::FilterArgs;
use litework_core::{CaptureIndex, OpenOptions, PcapFile, PcapWriter};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "litework",
    version,
    about = "Low-overhead pcap analysis — virtualizes huge captures for fast correlation",
    after_help = "\
FILTER FLAGS (work on every command; different flags AND together, repeating
a flag ORs within that field; values accept ranges/wildcards/CIDR):
  -p, --port <P>      --sport / --dport      port: 443, range 5900-5910
      --ip <A>        --ip.src / --ip.dst    IP: 10.0.0.1, '10.10.*.180', 10.0.0.0/8
  -m, --mac <M>       --mac.src / --mac.dst  MAC: aa:bb:cc:dd:ee:ff, 'aa:bb:*'
  -P, --proto <NAME>  tcp udp icmp arp ...   protocol name or IP proto number
      --vlan <ID>     -f, --filter '<expr>'  raw filter expression

FILTER LANGUAGE (for -f and the query/export expression argument):
  fields     mac mac_src mac_dst ip ip_src ip_dst proto port sport dport
             ethertype vlan len
  operators  ==  !=  <  >  <=  >=  in {a, b, c}  &&  ||  !  ( )
  values     ranges 5900-5910 · IP wildcards 10.10.*.180 / prefix 10.10.*
             CIDR 192.168.1.0/24, fe80::/10 · MAC wildcards aa:bb:*:*:*:01

EXAMPLES:
  litework cap.pcap                                open the TUI
  litework cap.pcap -p 5901 --ip.src 8.8.8.8       TUI, pre-filtered
  litework cap.pcap --ip 192.168.1.0/24            who's in this subnet?
  litework cap.pcap --ip '10.10.*.180'             I only know part of the IP
  litework stats cap.pcap                          quick overview report
  litework query cap.pcap 'port == 5900-5910'      port range hunt
  litework query cap.pcap -P tcp -P udp -p 53      shorthand flags
  litework export cap.pcap out.pcap --ip 10.0.0.9  save matches as a pcap
  litework -i eth0                                 live TUI on an interface
  litework -i eth0 -p 53 --ip '10.0.*'             live TUI, pre-filtered
  litework capture -i eth0                         stream packet lines (headless)
  litework capture -i eth0 -w live.pcap -p 53      capture DNS to a file

Quote wildcard values ('10.10.*') so your shell doesn't expand them.
Run litework <COMMAND> --help for detailed per-command examples."
)]
struct Cli {
    /// Capture file to open in the TUI (equivalent to `litework view <FILE>`).
    file: Option<PathBuf>,

    /// Open the TUI live on an interface instead of a file (Linux; needs
    /// root or CAP_NET_RAW). Spools to a temp file — you choose to keep or
    /// discard it on quit, or spool straight to -w.
    #[arg(short = 'i', long, conflicts_with = "file")]
    interface: Option<String>,

    /// Spool the live capture to this pcap (kept; no quit prompt).
    #[arg(short = 'w', long, requires = "interface")]
    write: Option<PathBuf>,

    /// Don't put the live interface in promiscuous mode.
    #[arg(long, requires = "interface")]
    no_promisc: bool,

    #[command(flatten)]
    filter: FilterArgs,

    /// Memory budget (MB) for cached index columns.
    #[arg(long, global = true, default_value_t = 512, value_name = "MB")]
    mem: usize,

    /// Persist the index as a .lwix sidecar next to the capture (~1-3% of
    /// its size): reopening becomes instant and queries run off compressed
    /// columns. Without it, nothing is written to disk.
    #[arg(long = "index", global = true)]
    index: bool,

    /// Ignore any existing sidecar and rebuild the index.
    #[arg(long, global = true)]
    reindex: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Summarize a capture: protocol mix, top MACs, ports, time histogram.
    #[command(after_help = "\
EXAMPLES:
  litework stats cap.pcap                 human report: proto mix, top MACs
                                          (with the protocols each speaks),
                                          top ports, traffic histogram
  litework stats cap.pcap --top 25        longer top lists
  litework stats cap.pcap --json          full stats as JSON
  litework stats cap.pcap --json | jq '.top_macs[].mac'
  litework stats cap.pcap --json | jq '.protocols'

The first open builds the .lwix index sidecar; later opens are instant.")]
    Stats {
        file: PathBuf,
        /// Emit machine-readable JSON instead of the report.
        #[arg(long)]
        json: bool,
        /// How many top MACs / ports to show.
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
    /// Run a filter over a capture using tier-0 pruning.
    #[command(after_help = "\
EXAMPLES:
  litework query cap.pcap 'proto == tcp && dport == 443'
  litework query cap.pcap 'port == 5900-5910'            port range
  litework query cap.pcap 'ip == 10.10.*.180'            wildcard octet
  litework query cap.pcap 'ip == 192.168.1.0/24'         whole subnet
  litework query cap.pcap 'mac == aa:bb:*'               MAC vendor prefix
  litework query cap.pcap 'ip in {10.0.0.1, 10.0.0.9} && !(proto == arp)'
  litework query cap.pcap -P tcp -P udp -p 53            flags instead of expr
  litework query cap.pcap -f 'len > 1200' --ip '10.0.*'  mix flags + expr
  litework query cap.pcap 'port == 4444' --count         just the count
  litework query cap.pcap 'proto == udp' --json --limit 0 | jq .ip_src

Flags and the expression AND together. --limit 0 means unlimited.")]
    Query {
        file: PathBuf,
        /// Filter expression, e.g. 'mac == aa:bb:cc:dd:ee:ff && proto == tcp'.
        expr: Option<String>,
        #[command(flatten)]
        filter: FilterArgs,
        /// Emit JSON lines, one per matching packet.
        #[arg(long)]
        json: bool,
        /// Stop after this many matches (0 = unlimited).
        #[arg(long, default_value_t = 100)]
        limit: u64,
        /// Print only the match count and scan statistics.
        #[arg(long)]
        count: bool,
    },
    /// Write matching packets out to a new pcap (readable by any tool).
    #[command(after_help = "\
EXAMPLES:
  litework export cap.pcap dns.pcap -p 53                DNS traffic only
  litework export cap.pcap host.pcap --ip 10.0.0.9       one host's traffic
  litework export cap.pcap subnet.pcap --ip 10.10.0.0/16 a whole subnet
  litework export cap.pcap weird.pcap 'port == 5900-5910 && proto == tcp'
  litework export big.pcapng slice.pcap --limit 10000    first 10k matches

Output is a nanosecond-precision pcap that opens in LiteWork, Wireshark,
or tcpdump. In the TUI, 'w' does the same for the current filter.")]
    Export {
        /// Source capture (pcap or pcapng).
        file: PathBuf,
        /// Output pcap path.
        out: PathBuf,
        /// Filter expression (optional if filter flags are given).
        expr: Option<String>,
        #[command(flatten)]
        filter: FilterArgs,
        /// Stop after this many packets (0 = all matches).
        #[arg(long, default_value_t = 0)]
        limit: u64,
    },
    /// (Re)build the .lwix index sidecar for a capture and report timing.
    #[command(after_help = "\
EXAMPLES:
  litework index cap.pcap        build/refresh cap.pcap.lwix
  litework index cap.pcap --mem 128   cap column-cache RAM at 128 MB

The sidecar makes reopening instant and queries run off compressed columns
without touching the capture. Nothing is written on a normal open unless you
pass --index; this command always writes (and rebuilds) the sidecar.")]
    Index { file: PathBuf },
    /// Capture live from an interface (Ctrl-C to stop). With -w, packets are
    /// written to a pcap; without it they stream to stdout as text lines.
    /// With no -i, lists available interfaces.
    #[command(after_help = "\
EXAMPLES:
  litework capture                            list interfaces
  litework capture -i eth0                    stream packets to the terminal
  litework capture -i eth0 -p 53              stream only DNS
  litework capture -i eth0 --ip '10.0.*' -P tcp --json | jq .ip_dst
  litework capture -i eth0 -w out.pcap        capture to a file (rate readout)
  litework capture -i eth0 -w dns.pcap -p 53 --seconds 60
  litework capture -i eth0 -w x.pcap -c 100000   stop after 100k packets

Needs root or:  sudo setcap cap_net_raw,cap_net_admin=eip $(command -v litework)
Filters apply at capture time — only matching packets are written/shown.")]
    Capture {
        /// Interface name (e.g. eth0). Omit to list interfaces.
        #[arg(short = 'i', long)]
        interface: Option<String>,
        /// Write packets to this pcap instead of streaming to stdout.
        #[arg(short = 'w', long)]
        write: Option<PathBuf>,
        /// Stream packets as JSON lines instead of text (stdout mode).
        #[arg(long)]
        json: bool,
        /// Stop after this many packets.
        #[arg(short = 'c', long)]
        count: Option<u64>,
        /// Stop after this many seconds.
        #[arg(long)]
        seconds: Option<u64>,
        /// Don't put the interface in promiscuous mode.
        #[arg(long)]
        no_promisc: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Open the interactive TUI (default when given just a file).
    #[command(after_help = "\
EXAMPLES:
  litework view cap.pcap                      same as: litework cap.pcap
  litework view cap.pcap -p 5000-5999         open pre-filtered

TUI KEYS:
  1-5 / tab   OVERVIEW · PACKETS · MACS · PORTS · FLOWS
  /           filter bar with completion (tab completes, ? shows syntax)
  enter       packets: dissection + hex/ascii pane · tables: pivot to packets
  w           save current filter matches to a pcap
  ?           filter syntax reference
  g/G pgup/pgdn ↑↓   navigate · esc clear/back · q quit

With a filter active, MACS/PORTS/FLOWS aggregate only matching traffic.")]
    View {
        file: PathBuf,
        #[command(flatten)]
        filter: FilterArgs,
    },
}

fn main() -> Result<()> {
    // Die quietly when piped into `head` etc. instead of panicking on EPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let open = OpenCfg {
        mem_mb: cli.mem,
        index: cli.index,
        reindex: cli.reindex,
    };
    match (cli.cmd, cli.file) {
        (Some(Cmd::Stats { file, json, top }), _) => stats(&file, &open, json, top),
        (Some(Cmd::Query { file, expr, filter, json, limit, count }), _) => {
            let expr = filter.compose(expr.as_deref())?;
            query(&file, &open, &expr, json, limit, count)
        }
        (Some(Cmd::Export { file, out, expr, filter, limit }), _) => {
            let expr = filter.compose_or_all(expr.as_deref())?;
            export(&file, &open, &out, &expr, limit)
        }
        (Some(Cmd::Index { file }), _) => index_cmd(&file, &open),
        (Some(Cmd::Capture { interface, write, json, count, seconds, no_promisc, filter }), _) => {
            capture_cmd::run(interface, write, json, count, seconds, no_promisc, &filter)
        }
        (Some(Cmd::View { file, filter }), _) => view(&file, &open, &filter),
        (None, Some(file)) => view(&file, &open, &cli.filter),
        (None, None) => match cli.interface {
            Some(iface) => view_live(&iface, cli.write, cli.no_promisc, &cli.filter),
            None => bail!("usage: litework <FILE>, litework -i <IFACE>, or litework <COMMAND> (see --help)"),
        },
    }
}

/// CLI-level open configuration (from the global flags).
pub struct OpenCfg {
    pub mem_mb: usize,
    pub index: bool,
    pub reindex: bool,
}

fn open_indexed(path: &Path, cfg: &OpenCfg) -> Result<(PcapFile, CaptureIndex)> {
    let file = PcapFile::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut opts = OpenOptions::for_capture(&file);
    opts.persist = cfg.index;
    opts.mem_limit_bytes = cfg.mem_mb.max(16) << 20;
    opts.force_rebuild = cfg.reindex;
    let progress_tty = std::io::stderr().is_terminal();
    let mut last_pct = u64::MAX;
    let index = CaptureIndex::open(&file, &opts, |done, total| {
        if progress_tty && total > 0 {
            let pct = done * 100 / total;
            if pct != last_pct {
                last_pct = pct;
                eprint!("\rindexing... {pct}%");
                let _ = std::io::stderr().flush();
            }
        }
    })?;
    if progress_tty {
        eprint!("\r\x1b[K");
    }
    if let Some(w) = &index.warning {
        eprintln!("warning: {w}");
    }
    // Discoverability nudge: big capture, no sidecar in play.
    if progress_tty && index.sidecar.is_none() && file.len() > 200 << 20 {
        eprintln!(
            "tip: add --index to save a .lwix index next to the capture — later opens are instant"
        );
    }
    Ok((file, index))
}

fn stats(path: &Path, cfg: &OpenCfg, json: bool, top: usize) -> Result<()> {
    let (file, index) = open_indexed(path, cfg)?;
    if json {
        output::stats_json(&file, &index, top)
    } else {
        output::stats_report(&file, &index, top)
    }
}

fn query(path: &Path, cfg: &OpenCfg, expr_src: &str, json: bool, limit: u64, count_only: bool) -> Result<()> {
    let expr = litework_core::parse_filter(expr_src)?;
    let (file, index) = open_indexed(path, cfg)?;
    output::query_report(&file, &index, &expr, json, limit, count_only)
}

fn export(path: &Path, cfg: &OpenCfg, out: &Path, expr_src: &str, limit: u64) -> Result<()> {
    let expr = litework_core::parse_filter(expr_src)?;
    let (file, index) = open_indexed(path, cfg)?;
    let mut writer: Option<PcapWriter> = None;
    let mut written = 0u64;
    let run = litework_core::run_query(&file, &index, &expr, |rec, _meta| {
        let data = file.bytes(rec);
        let w = match &mut writer {
            Some(w) => w,
            None => {
                writer = Some(PcapWriter::create(out, rec.linktype).expect("create output"));
                writer.as_mut().unwrap()
            }
        };
        w.write(rec.ts_nanos, rec.origlen, rec.linktype, data)
            .expect("write packet");
        written += 1;
        limit == 0 || written < limit
    })?;
    match writer {
        None => println!("0 matches — nothing written, {} not created", out.display()),
        Some(w) => {
            let (pkts, bytes, skipped) = w.finish()?;
            println!(
                "{}: {} packets, {} ({} matches in source)",
                out.display(),
                pkts,
                litework_core::types::fmt_bytes(bytes),
                run.matched
            );
            if skipped > 0 {
                println!("note: {skipped} packets skipped (different linktype than the first packet)");
            }
        }
    }
    Ok(())
}

fn index_cmd(path: &Path, cfg: &OpenCfg) -> Result<()> {
    // `index` exists to build the sidecar: always persist, always rebuild.
    let cfg = OpenCfg { mem_mb: cfg.mem_mb, index: true, reindex: true };
    let (file, index) = open_indexed(path, &cfg)?;
    println!(
        "{}: {} packets in {} row groups, indexed {:.1} MB in {} ms ({:.0} MB/s)",
        path.display(),
        index.stats.packets,
        index.groups.len(),
        file.len() as f64 / 1e6,
        index.build_millis,
        file.len() as f64 / 1e3 / index.build_millis.max(1) as f64,
    );
    if index.sidecar.is_some() {
        println!("sidecar: {}", litework_core::sidecar::sidecar_path(path).display());
    }
    if index.truncated {
        println!("note: capture is truncated; indexed everything before the cut");
    }
    Ok(())
}

fn view(path: &Path, cfg: &OpenCfg, filter: &FilterArgs) -> Result<()> {
    let initial = filter.compose_opt(None)?;
    let (file, index) = open_indexed(path, cfg)?;
    tui::run(file, index, initial)
}

fn view_live(
    iface: &str,
    write: Option<PathBuf>,
    no_promisc: bool,
    filter: &FilterArgs,
) -> Result<()> {
    let initial = filter.compose_opt(None)?;
    let live = tui::live::start(iface, write, !no_promisc)?;
    // The spool exists with a flushed header; open it like any capture.
    let file = PcapFile::open(&live.spool_path)
        .with_context(|| format!("opening spool {}", live.spool_path.display()))?;
    let index = CaptureIndex::build_in_memory(&file, |_, _| {})?;
    tui::run_live(file, index, initial, live)
}

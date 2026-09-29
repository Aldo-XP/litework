//! `lwz` — standalone format-aware compressor for packet captures.
//!
//! Input is an NDJSON file of DVB-S2 baseband-frame records
//! (`{"timestamp":..,"bbframe":"<base64>","metadata":{..}}`) or a legacy pcap;
//! the format is detected from the first bytes. Output is a `.lwz` archive
//! that `lwz unpack` restores byte-for-byte.

mod cli;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "lwz",
    version,
    about = "Format-aware lossless compression for bbframe NDJSON and pcap captures",
    after_help = "\
HOW IT WORKS
  Each line is taken apart: base64 decoded (-25% for free), timestamps turned
  into deltas, BBHEADER fields and GSE headers put in their own columns, and
  every IP packet inside the frame modelled from per-flow state so headers,
  checksums and lengths cost almost nothing. Payloads are grouped by protocol
  and flow. Every column is then LZMA-compressed. Anything that doesn't parse
  is stored verbatim — output is always byte-exact.

EXAMPLES
  lwz pack frames.ndjson                   -> frames.ndjson.lwz
  lwz pack frames.ndjson --stats --verify  show where the bytes went, then
                                           unpack in memory and compare
  lwz pack frames.ndjson --strict          refuse malformed lines
  lwz pack frames.ndjson -o /mnt/arch/f.lwz --level 6 -j 8
  lwz pack - < frames.ndjson > f.lwz       streaming
  lwz unpack frames.ndjson.lwz             -> frames.ndjson
  lwz unpack f.lwz -o - | head             stream out"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compress an NDJSON (bbframe) or pcap file into a .lwz archive.
    Pack {
        /// Input file, or - for stdin.
        file: PathBuf,
        /// Output archive (default: <input>.lwz, or stdout when input is -).
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// LZMA effort 1-9 (9 = smallest, slowest).
        #[arg(long, default_value_t = 9)]
        level: u32,
        /// Raw input bytes per independently-compressed block (MB). Memory
        /// use is roughly 3x this.
        #[arg(long, default_value_t = 128, value_name = "MB")]
        block_mb: usize,
        /// Compression threads (default: all cores).
        #[arg(short = 'j', long)]
        threads: Option<usize>,
        /// Print a per-column breakdown of where the bytes went.
        #[arg(long)]
        stats: bool,
        /// After packing, unpack the archive in memory and compare to the input.
        #[arg(long)]
        verify: bool,
        /// Fail on the first line that isn't a well-formed bbframe record
        /// (default: such lines are kept verbatim and counted).
        #[arg(long)]
        strict: bool,
    },
    /// Restore a .lwz archive to the original file, byte for byte.
    Unpack {
        /// Archive, or - for stdin.
        file: PathBuf,
        /// Output path (default: input without .lwz, or stdout when input is -).
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Pack { file, out, level, block_mb, threads, stats, verify, strict } => {
            cli::pack(&file, out.as_deref(), level, block_mb, threads, stats, verify, strict)
        }
        Cmd::Unpack { file, out } => cli::unpack(&file, out.as_deref()),
    }
}

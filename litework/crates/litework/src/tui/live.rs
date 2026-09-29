//! Live capture into the TUI: a capture thread appends packets to a spool
//! pcap and streams them over a channel; the TUI drains the channel each
//! tick, appending to the in-memory index so every tab updates in place.

use anyhow::{Context, Result};
use litework_core::types::PacketRecord;
use litework_core::PcapWriter;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum Msg {
    Pkt(PacketRecord, Vec<u8>),
    /// Cumulative kernel counters (received, dropped).
    Stats(u64, u64),
}

pub struct Live {
    pub iface: String,
    pub rx: crossbeam_channel::Receiver<Msg>,
    tx: crossbeam_channel::Sender<Msg>,
    pub stop: Arc<AtomicBool>,
    pub spool_path: PathBuf,
    /// True when spooling to a temp file (ask keep/discard on quit).
    pub temp: bool,
    pub promisc: bool,
    /// Capture thread is running (Space toggles stop/resume).
    pub running: bool,
    // rate bookkeeping
    pub kernel_recv: u64,
    pub kernel_drop: u64,
    pub rate: f64,
    pub last_rate_at: Instant,
    pub last_rate_pkts: u64,
    /// Packet list follows the newest packet until the user scrolls up.
    pub follow: bool,
    /// Whole-session aggregates for the MACS/PORTS/FLOWS tabs.
    pub agg: super::tables::FilteredStats,
}

/// Spawn the capture thread. The spool file exists (header flushed) when this
/// returns, so the caller can immediately open it as a `PcapFile`.
pub fn start(
    iface: &str,
    spool: Option<PathBuf>,
    promisc: bool,
) -> Result<Live> {
    let src =
        litework_capture::open(iface, promisc).with_context(|| format!("opening {iface}"))?;
    let linktype = src.linktype();
    let (spool_path, temp) = match spool {
        Some(p) => (p, false),
        None => {
            clean_stale_spools();
            let p = std::env::temp_dir().join(format!(
                "litework-live-{}-{}.pcap",
                iface.replace('/', "_"),
                std::process::id()
            ));
            (p, true)
        }
    };
    let mut writer = PcapWriter::create(&spool_path, linktype)?;
    writer.flush()?; // header on disk before the TUI mmaps it

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = crossbeam_channel::bounded::<Msg>(65_536);
    spawn_thread(src, writer, 24, stop.clone(), tx.clone(), iface)?;

    Ok(Live {
        iface: iface.to_string(),
        rx,
        tx,
        stop,
        spool_path,
        temp,
        promisc,
        running: true,
        kernel_recv: 0,
        kernel_drop: 0,
        rate: 0.0,
        last_rate_at: Instant::now(),
        last_rate_pkts: 0,
        follow: true,
        agg: Default::default(),
    })
}

fn spawn_thread(
    mut src: Box<dyn litework_capture::Source + Send>,
    mut writer: PcapWriter,
    start_offset: u64,
    stop: Arc<AtomicBool>,
    tx: crossbeam_channel::Sender<Msg>,
    iface: &str,
) -> Result<()> {
    let linktype = src.linktype();
    std::thread::Builder::new()
        .name(format!("capture-{iface}"))
        .spawn(move || {
            // Offset of the next record in the spool.
            let mut offset: u64 = start_offset;
            let mut last_flush = Instant::now();
            let mut last_stats = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                match src.next() {
                    Ok(Some(p)) => {
                        let caplen = p.data.len() as u32;
                        let rec = PacketRecord {
                            ts_nanos: p.ts_nanos,
                            record_offset: offset,
                            data_offset: offset + 16,
                            caplen,
                            origlen: p.origlen,
                            linktype,
                        };
                        if writer.write(p.ts_nanos, p.origlen, linktype, p.data).is_err() {
                            break; // disk full / spool gone — stop capturing
                        }
                        offset += 16 + caplen as u64;
                        // If the UI is behind, block briefly; timeout drops the
                        // packet from the UI (it is still in the spool).
                        let _ = tx.send_timeout(
                            Msg::Pkt(rec, p.data.to_vec()),
                            Duration::from_millis(50),
                        );
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
                if last_flush.elapsed() >= Duration::from_millis(100) {
                    let _ = writer.flush();
                    last_flush = Instant::now();
                }
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    if let Some((r, d)) = src.stats() {
                        let _ = tx.try_send(Msg::Stats(r, d));
                    }
                    last_stats = Instant::now();
                }
            }
            let _ = writer.flush();
        })?;
    Ok(())
}

/// Remove temp spools left behind by crashed/killed sessions (>1 day old).
fn clean_stale_spools() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("litework-live-") && name.ends_with(".pcap") {
            let stale = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age.as_secs() > 86_400)
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

impl Live {
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.running = false;
    }

    /// Restart capture, appending to the existing spool.
    pub fn resume(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        let src = litework_capture::open(&self.iface, self.promisc)
            .with_context(|| format!("reopening {}", self.iface))?;
        let linktype = src.linktype();
        // Give the old thread a beat to flush its tail, then append after it.
        std::thread::sleep(Duration::from_millis(150));
        let offset = std::fs::metadata(&self.spool_path)?.len();
        let writer = PcapWriter::append_to(&self.spool_path, linktype)?;
        self.stop = Arc::new(AtomicBool::new(false));
        spawn_thread(src, writer, offset, self.stop.clone(), self.tx.clone(), &self.iface)?;
        self.running = true;
        Ok(())
    }

    pub fn discard_spool(&mut self) {
        self.shutdown();
        std::thread::sleep(Duration::from_millis(150)); // let the writer close
        let _ = std::fs::remove_file(&self.spool_path);
    }
}

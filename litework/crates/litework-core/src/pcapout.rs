//! Writing packets out to a legacy pcap file (nanosecond-magic variant, which
//! Wireshark/tcpdump read natively). Used by `litework export`, the TUI's
//! save key, and live capture.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub struct PcapWriter {
    w: BufWriter<File>,
    linktype: u16,
    pub packets: u64,
    pub bytes: u64,
    /// Packets skipped because their linktype differed from the file's.
    pub skipped_linktype: u64,
}

impl PcapWriter {
    pub fn create(path: &Path, linktype: u16) -> io::Result<Self> {
        let mut w = BufWriter::new(File::create(path)?);
        w.write_all(&0xa1b2_3c4du32.to_le_bytes())?; // nanosecond pcap magic
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&[0u8; 8])?; // thiszone, sigfigs
        w.write_all(&65_535u32.to_le_bytes())?; // snaplen
        w.write_all(&(linktype as u32).to_le_bytes())?;
        Ok(PcapWriter {
            w,
            linktype,
            packets: 0,
            bytes: 0,
            skipped_linktype: 0,
        })
    }

    /// Append one packet. Packets whose linktype doesn't match the file header
    /// are counted in `skipped_linktype` rather than corrupting the output.
    pub fn write(
        &mut self,
        ts_nanos: u64,
        origlen: u32,
        linktype: u16,
        data: &[u8],
    ) -> io::Result<()> {
        if linktype != self.linktype {
            self.skipped_linktype += 1;
            return Ok(());
        }
        self.w
            .write_all(&((ts_nanos / 1_000_000_000) as u32).to_le_bytes())?;
        self.w
            .write_all(&((ts_nanos % 1_000_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(&origlen.max(data.len() as u32).to_le_bytes())?;
        self.w.write_all(data)?;
        self.packets += 1;
        self.bytes += data.len() as u64;
        Ok(())
    }

    /// Reopen an existing pcap for appending (live capture resume). The
    /// header is already on disk; `linktype` must match it.
    pub fn append_to(path: &Path, linktype: u16) -> io::Result<Self> {
        let f = std::fs::OpenOptions::new().append(true).open(path)?;
        Ok(PcapWriter {
            w: BufWriter::new(f),
            linktype,
            packets: 0,
            bytes: 0,
            skipped_linktype: 0,
        })
    }

    /// Flush buffered records to disk (live spooling reads behind the writer).
    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }

    pub fn finish(mut self) -> io::Result<(u64, u64, u64)> {
        self.w.flush()?;
        Ok((self.packets, self.bytes, self.skipped_linktype))
    }
}

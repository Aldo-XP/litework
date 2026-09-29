//! litework-core: the headless engine behind LiteWork.
//!
//! Virtualizes pcap/pcapng captures: a single sequential pass builds a small
//! tier-0 index (row-group summaries + global stats) and every later query
//! prunes to the few file regions that can match, re-reading raw bytes from
//! the mmap on demand. The capture itself is never loaded into memory.

pub mod annotate;
pub mod columns;
pub mod dissect;
pub mod format;
pub mod hist;
pub mod index;
pub mod kaitai;
pub mod pcapout;
pub mod sidecar;
pub mod query;
pub mod services;
pub mod sketch;
pub mod types;

pub use format::{CaptureFormat, FormatError, PcapFile};
pub use index::{CaptureIndex, OpenOptions, ROW_GROUP_SIZE};
pub use pcapout::PcapWriter;
pub use query::{parse as parse_filter, run_query, Expr, ParseError};
pub use types::{PacketMeta, PacketRecord, ProtoKey};

//! Live capture sources for LiteWork.
//!
//! v1 ships a pure-Rust AF_PACKET source on Linux. macOS (/dev/bpf) and
//! Windows (runtime-loaded Npcap) land as this module grows in M4 — the
//! `Source` trait is the seam they plug into. File analysis works everywhere
//! regardless.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("interface '{0}' not found")]
    NoSuchInterface(String),
    #[error("permission denied opening capture socket — run with sudo, or grant the binary CAP_NET_RAW:\n  sudo setcap cap_net_raw,cap_net_admin=eip $(command -v litework)")]
    Permission,
    #[error("live capture is not yet supported on this platform (file analysis works everywhere; Linux capture is available now, macOS/Windows arrive in M4)")]
    Unsupported,
}

/// One captured packet, borrowed from the source's buffer.
pub struct Captured<'a> {
    pub ts_nanos: u64,
    /// Original wire length (may exceed data.len() if truncated by snaplen).
    pub origlen: u32,
    pub data: &'a [u8],
}

/// A live packet source feeding the same pipeline as file reads.
pub trait Source: Send {
    /// Block up to ~100ms for the next packet; Ok(None) on timeout.
    fn next(&mut self) -> Result<Option<Captured<'_>>, CaptureError>;
    /// LINKTYPE_* of delivered packets.
    fn linktype(&self) -> u16;
    /// Cumulative (received, kernel-dropped) counts, when the platform
    /// exposes them.
    fn stats(&mut self) -> Option<(u64, u64)> {
        None
    }
}

/// Names of capturable interfaces on this machine.
pub fn interfaces() -> Vec<String> {
    #[cfg(unix)]
    {
        let mut names = Vec::new();
        unsafe {
            let list = libc::if_nameindex();
            if !list.is_null() {
                let mut p = list;
                while !(*p).if_name.is_null() {
                    names.push(
                        std::ffi::CStr::from_ptr((*p).if_name)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    p = p.add(1);
                }
                libc::if_freenameindex(list);
            }
        }
        names
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// Open the platform's live source for `iface`.
pub fn open(iface: &str, promisc: bool) -> Result<Box<dyn Source + Send>, CaptureError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(afpacket::AfPacketSource::open(iface, promisc)?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (iface, promisc);
        Err(CaptureError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
mod afpacket {
    use super::{Captured, CaptureError, Source};
    use std::ffi::CString;
    use std::io;

    const SNAPLEN: usize = 65_535;

    pub struct AfPacketSource {
        fd: i32,
        buf: Vec<u8>,
        /// Wire length of the packet currently in `buf` (recv MSG_TRUNC).
        last_wire: usize,
        /// Accumulated kernel counters (PACKET_STATISTICS resets on read).
        total_recv: u64,
        total_drop: u64,
    }

    impl AfPacketSource {
        pub fn open(iface: &str, promisc: bool) -> Result<Self, CaptureError> {
            let eth_p_all_be = (libc::ETH_P_ALL as u16).to_be();
            // Safety: plain libc socket calls with locally-owned values.
            unsafe {
                let fd = libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    eth_p_all_be as i32,
                );
                if fd < 0 {
                    let e = io::Error::last_os_error();
                    return Err(if e.kind() == io::ErrorKind::PermissionDenied {
                        CaptureError::Permission
                    } else {
                        CaptureError::Io(e)
                    });
                }
                let cname = CString::new(iface).map_err(|_| {
                    CaptureError::NoSuchInterface(iface.to_string())
                })?;
                let ifindex = libc::if_nametoindex(cname.as_ptr());
                if ifindex == 0 {
                    libc::close(fd);
                    return Err(CaptureError::NoSuchInterface(iface.to_string()));
                }
                let mut sll: libc::sockaddr_ll = std::mem::zeroed();
                sll.sll_family = libc::AF_PACKET as u16;
                sll.sll_protocol = eth_p_all_be;
                sll.sll_ifindex = ifindex as i32;
                let rc = libc::bind(
                    fd,
                    &sll as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as u32,
                );
                if rc < 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(CaptureError::Io(e));
                }
                if promisc {
                    let mut mreq: libc::packet_mreq = std::mem::zeroed();
                    mreq.mr_ifindex = ifindex as i32;
                    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
                    // Best-effort: some virtual interfaces refuse promisc.
                    let _ = libc::setsockopt(
                        fd,
                        libc::SOL_PACKET,
                        libc::PACKET_ADD_MEMBERSHIP,
                        &mreq as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::packet_mreq>() as u32,
                    );
                }
                Ok(AfPacketSource {
                    fd,
                    buf: vec![0; SNAPLEN],
                    last_wire: 0,
                    total_recv: 0,
                    total_drop: 0,
                })
            }
        }
    }

    impl Source for AfPacketSource {
        fn next(&mut self) -> Result<Option<Captured<'_>>, CaptureError> {
            unsafe {
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = libc::poll(&mut pfd, 1, 100);
                if rc < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        return Ok(None); // signal (e.g. Ctrl-C) — let caller decide
                    }
                    return Err(CaptureError::Io(e));
                }
                if rc == 0 {
                    return Ok(None); // timeout
                }
                // MSG_TRUNC makes recv return the wire length even when the
                // packet exceeds our snaplen buffer.
                let n = libc::recv(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    libc::MSG_TRUNC,
                );
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        return Ok(None);
                    }
                    return Err(CaptureError::Io(e));
                }
                self.last_wire = n as usize;
                let caplen = self.last_wire.min(self.buf.len());
                let mut ts: libc::timespec = std::mem::zeroed();
                libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
                Ok(Some(Captured {
                    ts_nanos: ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64,
                    origlen: self.last_wire as u32,
                    data: &self.buf[..caplen],
                }))
            }
        }

        fn linktype(&self) -> u16 {
            1 // LINKTYPE_ETHERNET
        }

        fn stats(&mut self) -> Option<(u64, u64)> {
            // Safety: getsockopt with a properly sized tpacket_stats out-param.
            unsafe {
                let mut st: libc::tpacket_stats = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
                let rc = libc::getsockopt(
                    self.fd,
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    &mut st as *mut _ as *mut libc::c_void,
                    &mut len,
                );
                if rc == 0 {
                    self.total_recv += st.tp_packets as u64;
                    self.total_drop += st.tp_drops as u64;
                }
            }
            Some((self.total_recv, self.total_drop))
        }
    }

    impl Drop for AfPacketSource {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

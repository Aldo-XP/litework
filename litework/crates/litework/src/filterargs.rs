//! Shorthand filter flags that compose into the filter language, so common
//! hunts don't require writing an expression:
//!   litework cap.pcap -p 5901 --ip.src 8.8.8.8
//! Repeated flags for the same field OR together (`-P tcp -P udp` →
//! `proto in {tcp, udp}`); different fields AND together.

use anyhow::{bail, Result};
use clap::Args;

#[derive(Args, Default, Clone)]
pub struct FilterArgs {
    /// Match port (src or dst). Repeat for multiple.
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Vec<String>,
    /// Match source port.
    #[arg(long = "sport", alias = "port.src", value_name = "PORT")]
    pub sport: Vec<String>,
    /// Match destination port.
    #[arg(long = "dport", alias = "port.dst", value_name = "PORT")]
    pub dport: Vec<String>,
    /// Match IP (src or dst). Repeat for multiple.
    #[arg(long = "ip", value_name = "ADDR")]
    pub ip: Vec<String>,
    /// Match source IP.
    #[arg(long = "ip-src", alias = "ip.src", value_name = "ADDR")]
    pub ip_src: Vec<String>,
    /// Match destination IP.
    #[arg(long = "ip-dst", alias = "ip.dst", value_name = "ADDR")]
    pub ip_dst: Vec<String>,
    /// Match MAC (src or dst). Repeat for multiple.
    #[arg(short = 'm', long = "mac", value_name = "MAC")]
    pub mac: Vec<String>,
    /// Match source MAC.
    #[arg(long = "mac-src", alias = "mac.src", value_name = "MAC")]
    pub mac_src: Vec<String>,
    /// Match destination MAC.
    #[arg(long = "mac-dst", alias = "mac.dst", value_name = "MAC")]
    pub mac_dst: Vec<String>,
    /// Match protocol (tcp, udp, icmp, arp, ... or IP proto number). Repeat for multiple.
    #[arg(short = 'P', long = "proto", value_name = "PROTO")]
    pub proto: Vec<String>,
    /// Match VLAN id.
    #[arg(long = "vlan", value_name = "ID")]
    pub vlan: Vec<String>,
    /// Raw filter expression, ANDed with the flags above.
    #[arg(short = 'f', long = "filter", value_name = "EXPR")]
    pub filter: Option<String>,
}

impl FilterArgs {
    fn parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        let mut add = |field: &str, vals: &[String]| match vals.len() {
            0 => {}
            1 => parts.push(format!("{field} == {}", vals[0])),
            _ => parts.push(format!("{field} in {{{}}}", vals.join(", "))),
        };
        add("port", &self.port);
        add("sport", &self.sport);
        add("dport", &self.dport);
        add("ip", &self.ip);
        add("ip_src", &self.ip_src);
        add("ip_dst", &self.ip_dst);
        add("mac", &self.mac);
        add("mac_src", &self.mac_src);
        add("mac_dst", &self.mac_dst);
        add("proto", &self.proto);
        add("vlan", &self.vlan);
        if let Some(f) = &self.filter {
            parts.push(format!("({f})"));
        }
        parts
    }

    /// Compose flags + optional positional expression. None if nothing given.
    pub fn compose_opt(&self, expr: Option<&str>) -> Result<Option<String>> {
        let mut parts = self.parts();
        if let Some(e) = expr {
            parts.push(format!("({e})"));
        }
        if parts.is_empty() {
            return Ok(None);
        }
        let src = parts.join(" && ");
        // Validate now so flag typos fail fast with a good message.
        litework_core::parse_filter(&src)?;
        Ok(Some(src))
    }

    /// Compose, requiring at least one filter.
    pub fn compose(&self, expr: Option<&str>) -> Result<String> {
        match self.compose_opt(expr)? {
            Some(s) => Ok(s),
            None => bail!("no filter given — pass an expression or filter flags (-p, --ip, -P, ...)"),
        }
    }

    /// Compose, defaulting to match-everything (for export of whole captures).
    pub fn compose_or_all(&self, expr: Option<&str>) -> Result<String> {
        Ok(self
            .compose_opt(expr)?
            .unwrap_or_else(|| "len >= 0".to_string()))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_variants() {
        let mut f = FilterArgs {
            port: vec!["53".into()],
            proto: vec!["tcp".into(), "udp".into()],
            ip_src: vec!["8.8.8.8".into()],
            ..Default::default()
        };
        let s = f.compose(None).unwrap();
        assert_eq!(s, "port == 53 && ip_src == 8.8.8.8 && proto in {tcp, udp}");
        f.filter = Some("len > 100".into());
        assert!(f.compose(None).unwrap().ends_with("&& (len > 100)"));
        // bad value surfaces a parse error mentioning the value
        let bad = FilterArgs {
            mac: vec!["zz:zz".into()],
            ..Default::default()
        };
        assert!(bad.compose(None).is_err());
        assert!(FilterArgs::default().compose(None).is_err());
        assert_eq!(FilterArgs::default().compose_or_all(None).unwrap(), "len >= 0");
    }
}

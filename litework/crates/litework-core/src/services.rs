//! Protocol/service identification: port → service name (IANA registry +
//! curated overlay, ~6100 entries), IP protocol numbers (full IANA table),
//! and common ethertypes.

mod generated {
    include!("services_gen.rs");
}

pub use generated::{IP_PROTOCOLS, PORT_SERVICES};

/// Service name for a TCP/UDP port ("ssh", "dns", "vnc-1", ...).
pub fn service_name(port: u16) -> Option<&'static str> {
    PORT_SERVICES
        .binary_search_by_key(&port, |(p, _)| *p)
        .ok()
        .map(|i| PORT_SERVICES[i].1)
}

/// Keyword for an IP protocol number ("tcp", "gre", "ospf", ...).
pub fn ip_proto_name(n: u8) -> Option<&'static str> {
    IP_PROTOCOLS
        .binary_search_by_key(&n, |(p, _)| *p)
        .ok()
        .map(|i| IP_PROTOCOLS[i].1)
}

/// Reverse lookup: protocol keyword → number (accepts any IANA keyword).
pub fn ip_proto_by_name(name: &str) -> Option<u8> {
    IP_PROTOCOLS
        .iter()
        .find(|(_, kw)| *kw == name)
        .map(|(n, _)| *n)
}

/// Names for ethertypes an analyst is likely to meet (includes the ICS trio
/// GOOSE/GSE/SV — worth recognizing on sight in industrial captures).
pub static ETHERTYPES: &[(u16, &str)] = &[
    (0x0800, "ipv4"),
    (0x0806, "arp"),
    (0x22f0, "avtp"),
    (0x8035, "rarp"),
    (0x809b, "appletalk"),
    (0x8100, "vlan"),
    (0x86dd, "ipv6"),
    (0x8809, "slow-protocols"), // LACP/OAM
    (0x8847, "mpls"),
    (0x8848, "mpls-mcast"),
    (0x8863, "pppoe-disc"),
    (0x8864, "pppoe"),
    (0x888e, "eapol"),
    (0x8892, "profinet"),
    (0x88a8, "qinq"),
    (0x88b8, "goose"),
    (0x88b9, "gse"),
    (0x88ba, "sampled-values"),
    (0x88cc, "lldp"),
    (0x88e1, "homeplug-av"),
    (0x88e5, "macsec"),
    (0x88f7, "ptp"),
    (0x8906, "fcoe"),
    (0x8914, "fip"),
    (0x9000, "loopback-test"),
];

pub fn ethertype_name(t: u16) -> Option<&'static str> {
    ETHERTYPES
        .binary_search_by_key(&t, |(e, _)| *e)
        .ok()
        .map(|i| ETHERTYPES[i].1)
}

/// Reverse lookup for filter expressions ("arp", "lldp", "goose", ...).
pub fn ethertype_by_name(name: &str) -> Option<u16> {
    ETHERTYPES
        .iter()
        .find(|(_, kw)| *kw == name)
        .map(|(t, _)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(53), Some("dns")); // overlay beats IANA "domain"
        assert_eq!(service_name(19), Some("chargen")); // IANA-only
        assert_eq!(service_name(5901), Some("vnc-1")); // unofficial, overlay
        assert_eq!(service_name(27017), Some("mongodb"));
        assert_eq!(service_name(51820), Some("wireguard"));
        assert_eq!(service_name(48212), None); // unassigned stays honest
        assert!(PORT_SERVICES.len() > 5000);
        assert!(PORT_SERVICES.windows(2).all(|w| w[0].0 < w[1].0)); // sorted
    }

    #[test]
    fn known_protocols() {
        assert_eq!(ip_proto_name(6), Some("tcp"));
        assert_eq!(ip_proto_name(47), Some("gre"));
        assert_eq!(ip_proto_name(89), Some("ospf"));
        assert_eq!(ip_proto_name(112), Some("vrrp"));
        assert_eq!(ip_proto_by_name("ospf"), Some(89));
        assert_eq!(ip_proto_by_name("hopopt"), Some(0)); // any IANA keyword
        assert!(IP_PROTOCOLS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn known_ethertypes() {
        assert_eq!(ethertype_name(0x0806), Some("arp"));
        assert_eq!(ethertype_name(0x88b8), Some("goose"));
        assert_eq!(ethertype_by_name("lldp"), Some(0x88cc));
        assert!(ETHERTYPES.windows(2).all(|w| w[0].0 < w[1].0));
    }
}

#!/usr/bin/env python3
"""Regenerate crates/litework-core/src/services_gen.rs from the IANA
registries. Usage:
  curl -o ports.csv  https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
  curl -o protos.csv https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv
  python3 tools/gen_services.py ports.csv protos.csv > crates/litework-core/src/services_gen.rs
"""
import csv, sys

def main(ports_csv, protos_csv):
    by_port = {}
    with open(ports_csv, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            name = (row['Service Name'] or '').strip()
            port = (row['Port Number'] or '').strip()
            tp   = (row['Transport Protocol'] or '').strip().lower()
            desc = (row['Description'] or '').strip()
            if not name or not port or '-' in port:
                continue
            if any(w in desc.lower() for w in ('reserved', 'decommission', 'unassigned')):
                continue
            try:
                p = int(port)
            except ValueError:
                continue
            if p == 0 or p > 65535:
                continue
            rank = {'tcp': 0, 'udp': 1, 'sctp': 2, 'dccp': 3}.get(tp, 4)
            cur = by_port.get(p)
            if cur is None or rank < cur[0]:
                by_port[p] = (rank, name.lower())

    # Analyst-friendly + well-known unofficial names win over IANA's.
    overlay = {
      20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',67:'dhcp',68:'dhcp',
      69:'tftp',80:'http',88:'kerberos',110:'pop3',111:'rpcbind',123:'ntp',135:'msrpc',
      137:'netbios-ns',138:'netbios-dgm',139:'netbios-ssn',143:'imap',161:'snmp',162:'snmp-trap',
      179:'bgp',389:'ldap',443:'https',445:'smb',465:'smtps',500:'ike',514:'syslog',515:'lpd',
      520:'rip',546:'dhcpv6',547:'dhcpv6',587:'submission',631:'ipp',636:'ldaps',853:'dot',
      873:'rsync',902:'vmware',989:'ftps-data',990:'ftps',993:'imaps',995:'pop3s',
      1080:'socks',1194:'openvpn',1433:'mssql',1434:'mssql-udp',1521:'oracle',1723:'pptp',
      1812:'radius',1813:'radius-acct',1883:'mqtt',2049:'nfs',2375:'docker',2376:'docker-tls',
      2379:'etcd',3128:'squid',3260:'iscsi',3268:'ldap-gc',3306:'mysql',3389:'rdp',
      4369:'epmd',4444:'metasploit',4500:'ipsec-nat',5060:'sip',5061:'sips',5222:'xmpp',
      5353:'mdns',5355:'llmnr',5432:'postgres',5671:'amqps',5672:'amqp',5900:'vnc',
      5901:'vnc-1',5902:'vnc-2',5903:'vnc-3',5904:'vnc-4',5905:'vnc-5',5985:'winrm',
      5986:'winrm-tls',6379:'redis',6443:'kube-api',6514:'syslog-tls',6666:'irc',6667:'irc',
      8000:'http-alt',8008:'http-alt',8080:'http-proxy',8443:'https-alt',8888:'http-alt',
      9000:'php-fpm',9090:'prometheus',9100:'jetdirect',9200:'elasticsearch',9300:'es-transport',
      11211:'memcached',27017:'mongodb',51820:'wireguard',
    }
    for p, name in overlay.items():
        by_port[p] = (-1, name)
    ports = sorted((p, n) for p, (_, n) in by_port.items())

    protos = {}
    with open(protos_csv, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            d = (row['Decimal'] or '').strip()
            kw = (row['Keyword'] or '').strip()
            if not d.isdigit() or not kw or 'deprecated' in kw.lower():
                continue
            n = int(d)
            if n <= 255:
                protos[n] = kw.lower().split(' ')[0]
    protos.update({1:'icmp',2:'igmp',6:'tcp',17:'udp',41:'ipv6',47:'gre',50:'esp',51:'ah',
                   58:'icmpv6',88:'eigrp',89:'ospf',103:'pim',112:'vrrp',115:'l2tp',132:'sctp'})

    print("// GENERATED from the IANA Service Name & Port Number registry and the")
    print("// IANA Protocol Numbers registry, plus a curated overlay of")
    print("// analyst-friendly and well-known unofficial names.")
    print("// Regenerate with tools/gen_services.py — do not edit by hand.\n")
    print("/// (port, service) sorted by port for binary search.")
    print("pub static PORT_SERVICES: &[(u16, &str)] = &[")
    for p, n in ports:
        print(f'    ({p}, "{n}"),')
    print("];\n")
    print("/// (ip protocol number, name) sorted for binary search.")
    print("pub static IP_PROTOCOLS: &[(u8, &str)] = &[")
    for n, kw in sorted(protos.items()):
        print(f'    ({n}, "{kw}"),')
    print("];")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

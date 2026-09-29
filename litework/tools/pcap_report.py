#!/usr/bin/env python3
"""
pcap_report.py - full inventory of a pcap/pcapng: every MAC, IP, port,
conversation, flow, protocol, DNS name, TLS SNI and HTTP request, plus a time
histogram.  One streaming pass with `tshark -T fields`, aggregated here.

Output: a directory  <name>.report/  containing
  summary.json        capture facts
  histogram.csv       packets/bytes per time bucket, per transport
  protocols.csv       protocol hierarchy (frame.protocols chains) + _ws.col.Protocol
  macs.csv            every MAC: vendor, tx/rx packets+bytes, IPs seen behind it
  ips.csv             every IP (v4+v6): tx/rx, peers, MAC(s), ports served/used, first/last
  ports.csv           every (proto,port): packets, bytes, as-src/as-dst, distinct hosts, service name
  conversations.csv   every IP<->IP pair, both directions, protocols, first/last/duration
  flows.csv           every 5-tuple (proto src:sport <-> dst:dport), both directions, SYN/handshake
  dns.csv             every queried name: count, clients, resolvers, first/last
  tls_sni.csv         every TLS SNI: count, clients, servers, first/last
  http.csv            every host+method+uri+user-agent combo: count, clients, first/last
  report.html         all of the above, tabbed, searchable, sortable, offline, one file

Every CSV is complete (no row caps).  The HTML caps each table at --html-rows
(default 20000) so it stays snappy; the cap is stated in the page when hit.

Examples:
  pcap_report.py capture.pcap
  pcap_report.py capture.pcap -o /tmp/reports/          # output dir goes here
  pcap_report.py capture.pcap -Y 'ip.addr==10.0.0.5'    # only that host's traffic
  pcap_report.py big.pcap --fast --html-rows 5000
"""
import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import defaultdict

FIELDS = [
    "frame.time_epoch", "frame.len", "eth.src", "eth.dst", "eth.src.oui_resolved",
    "eth.dst.oui_resolved", "vlan.id", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "ip.proto", "ipv6.nxt", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "sctp.srcport", "sctp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "_ws.col.Protocol", "frame.protocols", "eth.type",
    "dns.qry.name", "dns.flags.response", "tls.handshake.extensions_server_name",
    "http.host", "http.request.method", "http.request.uri", "http.user_agent",
    "http.response.code", "arp.opcode",
]
F = {n: i for i, n in enumerate(FIELDS)}

IPPROTO = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah",
           58: "icmpv6", 89: "ospf", 132: "sctp"}


def die(msg):
    sys.stderr.write(f"pcap_report: {msg}\n")
    sys.exit(1)


def need(tool):
    if shutil.which(tool) is None:
        die(f"'{tool}' not found - install Wireshark CLI tools")


def capinfos(path):
    out = subprocess.run(["capinfos", "-T", "-m", "-r", "-a", "-e", "-c", "-d", "-u", "-S", "-t", "-i", path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        die(f"capinfos failed: {out.stderr.strip()}")
    row = next(csv.reader([out.stdout.strip().splitlines()[-1]]))
    try:
        # capinfos -T column order is fixed regardless of flag order:
        # name, type, packets, bytes, duration, start, end, data rate
        return {"file_type": row[1], "packets": int(row[2]), "bytes": int(row[3]), "duration": float(row[4]),
                "start": float(row[5]), "end": float(row[6])}
    except (ValueError, IndexError):
        die(f"could not parse capinfos output: {out.stdout!r}")


def pick_interval(duration, bins):
    nice = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30,
            60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400]
    raw = max(duration, 0.001) / max(bins, 1)
    return next((n for n in nice if n >= raw), nice[-1])


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="milliseconds")


_svc_cache = {}


def service(proto, port):
    k = (proto, port)
    if k not in _svc_cache:
        try:
            _svc_cache[k] = socket.getservbyport(port, proto)
        except (OSError, OverflowError):
            _svc_cache[k] = ""
    return _svc_cache[k]


class Agg:
    """A row of counters keyed by something; packets/bytes + first/last seen."""
    __slots__ = ("pk", "by", "first", "last", "x")

    def __init__(self):
        self.pk = 0; self.by = 0; self.first = None; self.last = 0.0; self.x = {}

    def hit(self, t, n):
        self.pk += 1; self.by += n
        if self.first is None or t < self.first:
            self.first = t
        if t > self.last:
            self.last = t


class Counter2:
    __slots__ = ("pk", "by")

    def __init__(self):
        self.pk = 0; self.by = 0


class Report:
    def __init__(self, interval, t0, top_peers=5):
        self.interval = interval; self.t0 = t0; self.top_peers = top_peers
        self.hist = defaultdict(lambda: defaultdict(int))       # bucket -> {frames,bytes,tcp..}
        self.macs = defaultdict(Agg)      # mac -> Agg, x: tx/rx Counter2, ips set, vendor
        self.ips = defaultdict(Agg)       # ip -> Agg, x: tx/rx, peers set, macs set, sports/dports counters
        self.ports = defaultdict(Agg)     # (proto,port) -> Agg, x: src/dst Counter2, hosts set
        self.convs = defaultdict(Agg)     # (a,b) sorted -> x: ab/ba Counter2, protos set, ports set
        self.flows = defaultdict(Agg)     # (proto,a,ap,b,bp) -> x: ab/ba, syn, synack, rst
        self.protos = defaultdict(Counter2)   # frame.protocols chain
        self.cols = defaultdict(Counter2)     # _ws.col.Protocol
        self.vlans = defaultdict(Counter2)
        self.dns = defaultdict(Agg)       # qname -> x: clients set, resolvers set, responses
        self.sni = defaultdict(Agg)       # sni -> x: clients, servers
        self.http = defaultdict(Agg)      # (host,method,uri,ua) -> x: clients, servers, codes
        self.n = 0; self.warn_lines = 0

    def packet(self, f):
        try:
            t = float(f[F["frame.time_epoch"]]); n = int(f[F["frame.len"]])
        except ValueError:
            self.warn_lines += 1; return
        self.n += 1
        rel = t - self.t0
        b = int(rel // self.interval) if rel >= 0 else 0
        smac, dmac = f[F["eth.src"]], f[F["eth.dst"]]
        sip = f[F["ip.src"]] or f[F["ipv6.src"]]
        dip = f[F["ip.dst"]] or f[F["ipv6.dst"]]
        pn = f[F["ip.proto"]] or f[F["ipv6.nxt"]]
        try:
            pnum = int(pn) if pn else None
        except ValueError:
            pnum = None
        l4 = IPPROTO.get(pnum, str(pnum) if pnum is not None else "")
        if not sip and f[F["eth.type"]] == "0x0806":
            l4 = "arp"
        sport = dport = None
        pp = None
        for pname in ("tcp", "udp", "sctp"):
            sp, dp = f[F[pname + ".srcport"]], f[F[pname + ".dstport"]]
            if sp and dp:
                try:
                    sport, dport, pp = int(sp), int(dp), pname
                except ValueError:
                    pass
                break

        # histogram
        h = self.hist[b]; h["frames"] += 1; h["bytes"] += n
        key = l4 if l4 in ("tcp", "udp", "icmp", "icmpv6", "arp") else "other"
        h[key + "_frames"] += 1; h[key + "_bytes"] += n

        # protocols
        c = self.protos[f[F["frame.protocols"]]]; c.pk += 1; c.by += n
        c = self.cols[f[F["_ws.col.Protocol"]]]; c.pk += 1; c.by += n
        if f[F["vlan.id"]]:
            c = self.vlans[f[F["vlan.id"]]]; c.pk += 1; c.by += n

        # macs
        for mac, dirn, ven in ((smac, "tx", f[F["eth.src.oui_resolved"]]), (dmac, "rx", f[F["eth.dst.oui_resolved"]])):
            if not mac:
                continue
            a = self.macs[mac]; a.hit(t, n)
            x = a.x
            if not x:
                x["tx"] = Counter2(); x["rx"] = Counter2(); x["ips"] = set(); x["vendor"] = ven
            x[dirn].pk += 1; x[dirn].by += n
            if ven and not x["vendor"]:
                x["vendor"] = ven
        if smac and sip:
            self.macs[smac].x["ips"].add(sip)
        if dmac and dip and not dmac.startswith(("ff:ff", "01:00:5e", "33:33")):
            self.macs[dmac].x["ips"].add(dip)

        # ips
        if sip and dip:
            for ip, dirn, peer, mac in ((sip, "tx", dip, smac), (dip, "rx", sip, dmac)):
                a = self.ips[ip]; a.hit(t, n); x = a.x
                if not x:
                    x["tx"] = Counter2(); x["rx"] = Counter2(); x["peers"] = set(); x["macs"] = set()
                    x["served"] = defaultdict(int); x["used"] = defaultdict(int); x["protos"] = set()
                x[dirn].pk += 1; x[dirn].by += n; x["peers"].add(peer)
                if mac:
                    x["macs"].add(mac)
                x["protos"].add(l4)
            if pp:
                # service side = lower port number (ephemeral ports are high); this keeps
                # a server's replies to client ports from being listed as "served"
                if dport <= sport:
                    self.ips[dip].x["served"][f"{pp}/{dport}"] += 1
                    self.ips[sip].x["used"][f"{pp}/{dport}"] += 1
                else:
                    self.ips[sip].x["served"][f"{pp}/{sport}"] += 1
                    self.ips[dip].x["used"][f"{pp}/{sport}"] += 1

            # conversations (unordered pair)
            if sip <= dip:
                ck, dirn = (sip, dip), "ab"
            else:
                ck, dirn = (dip, sip), "ba"
            a = self.convs[ck]; a.hit(t, n); x = a.x
            if not x:
                x["ab"] = Counter2(); x["ba"] = Counter2(); x["protos"] = set(); x["ports"] = set()
            x[dirn].pk += 1; x[dirn].by += n; x["protos"].add(l4)
            if pp:
                x["ports"].add(f"{pp}/{min(sport, dport)}")

        # ports + flows
        if pp:
            for port, dirn, host in ((sport, "src", sip), (dport, "dst", dip)):
                a = self.ports[(pp, port)]; a.hit(t, n); x = a.x
                if not x:
                    x["src"] = Counter2(); x["dst"] = Counter2(); x["hosts"] = set()
                x[dirn].pk += 1; x[dirn].by += n
                if host:
                    x["hosts"].add(host)
            if sip and dip:
                if (sip, sport) <= (dip, dport):
                    fk, dirn = (pp, sip, sport, dip, dport), "ab"
                else:
                    fk, dirn = (pp, dip, dport, sip, sport), "ba"
                a = self.flows[fk]; a.hit(t, n); x = a.x
                if not x:
                    x["ab"] = Counter2(); x["ba"] = Counter2(); x["syn"] = 0; x["synack"] = 0; x["rst"] = 0
                x[dirn].pk += 1; x[dirn].by += n
                if pp == "tcp":
                    syn, ack, rst = f[F["tcp.flags.syn"]], f[F["tcp.flags.ack"]], f[F["tcp.flags.reset"]]
                    if syn in ("1", "True"):
                        if ack in ("1", "True"):
                            x["synack"] += 1
                        else:
                            x["syn"] += 1
                    if rst in ("1", "True"):
                        x["rst"] += 1

        # L7
        q = f[F["dns.qry.name"]]
        if q:
            a = self.dns[q]; a.hit(t, n); x = a.x
            if not x:
                x["clients"] = set(); x["servers"] = set(); x["resp"] = 0
            if f[F["dns.flags.response"]] in ("1", "True"):
                x["resp"] += 1; x["clients"].add(dip); x["servers"].add(sip)
            else:
                x["clients"].add(sip); x["servers"].add(dip)
        s = f[F["tls.handshake.extensions_server_name"]]
        if s:
            a = self.sni[s]; a.hit(t, n); x = a.x
            if not x:
                x["clients"] = set(); x["servers"] = set()
            x["clients"].add(sip); x["servers"].add(f"{dip}:{dport}" if dport else dip)
        hh = f[F["http.host"]]; m = f[F["http.request.method"]]
        if m or hh:
            hk = (hh, m, f[F["http.request.uri"]], f[F["http.user_agent"]])
            a = self.http[hk]; a.hit(t, n); x = a.x
            if not x:
                x["clients"] = set(); x["servers"] = set()
            x["clients"].add(sip); x["servers"].add(f"{dip}:{dport}" if dport else dip)

    # ---- table builders ----------------------------------------------------
    def _top(self, d, k=None):
        k = k or self.top_peers
        return " ".join(f"{p}({c})" for p, c in sorted(d.items(), key=lambda kv: -kv[1])[:k])

    def t_hist(self):
        cols = ["t_rel", "t_epoch", "t_iso", "frames", "bytes", "frames_per_s", "bits_per_s"]
        keys = ["tcp", "udp", "icmp", "icmpv6", "arp", "other"]
        for k in keys:
            cols += [k + "_frames", k + "_bytes"]
        rows = []
        if not self.hist:
            return cols, rows
        for b in range(0, max(self.hist) + 1):
            h = self.hist.get(b, {})
            rel = b * self.interval
            r = [round(rel, 6), round(self.t0 + rel, 6), iso(self.t0 + rel), h.get("frames", 0), h.get("bytes", 0),
                 round(h.get("frames", 0) / self.interval, 3), round(h.get("bytes", 0) * 8 / self.interval, 3)]
            for k in keys:
                r += [h.get(k + "_frames", 0), h.get(k + "_bytes", 0)]
            rows.append(r)
        return cols, rows

    def t_macs(self):
        cols = ["mac", "vendor", "packets", "bytes", "tx_packets", "tx_bytes", "rx_packets", "rx_bytes",
                "ip_count", "ips", "first_seen", "last_seen"]
        rows = []
        for mac, a in self.macs.items():
            x = a.x
            ips = sorted(x["ips"])
            rows.append([mac, x["vendor"], a.pk, a.by, x["tx"].pk, x["tx"].by, x["rx"].pk, x["rx"].by,
                         len(ips), " ".join(ips[:20]) + (" ..." if len(ips) > 20 else ""), iso(a.first), iso(a.last)])
        rows.sort(key=lambda r: -r[2])
        return cols, rows

    def t_ips(self):
        cols = ["ip", "packets", "bytes", "tx_packets", "tx_bytes", "rx_packets", "rx_bytes", "peer_count",
                "protocols", "ports_served", "ports_used", "macs", "first_seen", "last_seen", "duration_s"]
        rows = []
        for ip, a in self.ips.items():
            x = a.x
            rows.append([ip, a.pk, a.by, x["tx"].pk, x["tx"].by, x["rx"].pk, x["rx"].by, len(x["peers"]),
                         " ".join(sorted(x["protos"])), self._top(x["served"]), self._top(x["used"]),
                         " ".join(sorted(x["macs"])), iso(a.first), iso(a.last), round(a.last - a.first, 3)])
        rows.sort(key=lambda r: -r[1])
        return cols, rows

    def t_ports(self):
        cols = ["proto", "port", "service", "packets", "bytes", "as_src_packets", "as_src_bytes",
                "as_dst_packets", "as_dst_bytes", "host_count", "first_seen", "last_seen"]
        rows = []
        for (pp, port), a in self.ports.items():
            x = a.x
            rows.append([pp, port, service(pp, port), a.pk, a.by, x["src"].pk, x["src"].by, x["dst"].pk, x["dst"].by,
                         len(x["hosts"]), iso(a.first), iso(a.last)])
        rows.sort(key=lambda r: -r[3])
        return cols, rows

    def t_convs(self):
        cols = ["ip_a", "ip_b", "packets", "bytes", "a_to_b_packets", "a_to_b_bytes", "b_to_a_packets",
                "b_to_a_bytes", "protocols", "dst_ports", "first_seen", "last_seen", "duration_s"]
        rows = []
        for (ia, ib), a in self.convs.items():
            x = a.x
            ports = sorted(x["ports"])
            rows.append([ia, ib, a.pk, a.by, x["ab"].pk, x["ab"].by, x["ba"].pk, x["ba"].by,
                         " ".join(sorted(x["protos"])), " ".join(ports[:15]) + (" ..." if len(ports) > 15 else ""),
                         iso(a.first), iso(a.last), round(a.last - a.first, 3)])
        rows.sort(key=lambda r: -r[2])
        return cols, rows

    def t_flows(self):
        cols = ["proto", "ip_a", "port_a", "ip_b", "port_b", "service", "packets", "bytes", "a_to_b_packets",
                "a_to_b_bytes", "b_to_a_packets", "b_to_a_bytes", "syn", "syn_ack", "rst", "state",
                "first_seen", "last_seen", "duration_s"]
        rows = []
        for (pp, ia, pa, ib, pb), a in self.flows.items():
            x = a.x
            svc = service(pp, pb) or service(pp, pa)
            if pp == "tcp":
                if x["syn"] and x["synack"]:
                    st = "handshake"
                elif x["syn"]:
                    st = "syn-no-reply"
                elif x["ba"].pk == 0 or x["ab"].pk == 0:
                    st = "one-way"
                else:
                    st = "mid-stream"
                if x["rst"]:
                    st += "+rst"
            else:
                st = "bidir" if x["ab"].pk and x["ba"].pk else "one-way"
            rows.append([pp, ia, pa, ib, pb, svc, a.pk, a.by, x["ab"].pk, x["ab"].by, x["ba"].pk, x["ba"].by,
                         x["syn"], x["synack"], x["rst"], st, iso(a.first), iso(a.last), round(a.last - a.first, 3)])
        rows.sort(key=lambda r: -r[6])
        return cols, rows

    def t_protos(self):
        cols = ["kind", "protocol", "packets", "bytes", "pct_packets"]
        tot = self.n or 1
        rows = [["chain", k, c.pk, c.by, round(100 * c.pk / tot, 2)] for k, c in self.protos.items()]
        rows += [["top", k, c.pk, c.by, round(100 * c.pk / tot, 2)] for k, c in self.cols.items()]
        rows += [["vlan", k, c.pk, c.by, round(100 * c.pk / tot, 2)] for k, c in self.vlans.items()]
        rows.sort(key=lambda r: (r[0], -r[2]))
        return cols, rows

    def t_dns(self):
        cols = ["name", "queries_and_responses", "responses", "client_count", "clients", "servers", "first_seen", "last_seen"]
        rows = [[q, a.pk, a.x["resp"], len(a.x["clients"]), " ".join(sorted(a.x["clients"])[:10]),
                 " ".join(sorted(a.x["servers"])[:5]), iso(a.first), iso(a.last)] for q, a in self.dns.items()]
        rows.sort(key=lambda r: -r[1])
        return cols, rows

    def t_sni(self):
        cols = ["server_name", "client_hellos", "client_count", "clients", "servers", "first_seen", "last_seen"]
        rows = [[s, a.pk, len(a.x["clients"]), " ".join(sorted(a.x["clients"])[:10]),
                 " ".join(sorted(a.x["servers"])[:5]), iso(a.first), iso(a.last)] for s, a in self.sni.items()]
        rows.sort(key=lambda r: -r[1])
        return cols, rows

    def t_http(self):
        cols = ["host", "method", "uri", "user_agent", "requests", "client_count", "clients", "servers", "first_seen", "last_seen"]
        rows = [[h, m, u, ua, a.pk, len(a.x["clients"]), " ".join(sorted(a.x["clients"])[:10]),
                 " ".join(sorted(a.x["servers"])[:5]), iso(a.first), iso(a.last)] for (h, m, u, ua), a in self.http.items()]
        rows.sort(key=lambda r: -r[4])
        return cols, rows


TABLES = [  # (file stem, tab title, builder, hint shown in the HTML)
    ("ips", "IPs", "t_ips", "every IPv4/IPv6 address. ports_served = destination ports others hit on this host; ports_used = destination ports it talked to"),
    ("conversations", "Conversations", "t_convs", "every IP pair, both directions; dst_ports = service ports (lower-numbered side) used between them"),
    ("flows", "Flows", "t_flows", "every 5-tuple. state: handshake = SYN and SYN/ACK seen; syn-no-reply = SYN(s) never answered (scans, closed/filtered ports); mid-stream = capture missed the handshake; one-way = traffic in a single direction; +rst = reset seen"),
    ("ports", "Ports", "t_ports", "every transport port seen on either side, with service name from /etc/services"),
    ("macs", "MACs", "t_macs", "every MAC with OUI vendor and the IPs seen behind it"),
    ("dns", "DNS", "t_dns", "every queried name"),
    ("tls_sni", "TLS SNI", "t_sni", "server names from TLS ClientHello"),
    ("http", "HTTP", "t_http", "cleartext HTTP requests"),
    ("protocols", "Protocols", "t_protos", "chain = full dissector chain (frame.protocols); top = Wireshark's Protocol column; vlan = 802.1Q tag"),
    ("histogram", "Histogram", "t_hist", "packets/bytes per time bucket (UTC)"),
]


def write_csv(path, cols, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols); w.writerows(rows)


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#fafafa;--fg:#1c1c1e;--muted:#6b6b72;--line:#e2e2e6;--card:#fff;--accent:#2f6fed;--hl:#fff3b0;--zebra:#f3f3f6}
@media(prefers-color-scheme:dark){:root{--bg:#121214;--fg:#ececf0;--muted:#9a9aa4;--line:#2a2a30;--card:#1b1b1f;--accent:#6b9cff;--hl:#5a4a00;--zebra:#202024}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1600px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:0 0 2px;font-weight:600}h1 small{color:var(--muted);font-weight:400;margin-left:8px;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin:12px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px}.card b{display:block;font-size:18px;font-weight:600}.card span{color:var(--muted);font-size:11px}
.tabs{display:flex;flex-wrap:wrap;gap:4px;margin:10px 0 8px}.tabs button{font:inherit;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;cursor:pointer}
.tabs button.on{background:var(--accent);color:#fff;border-color:var(--accent)}.tabs button i{font-style:normal;opacity:.7;margin-left:4px}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
input[type=search]{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);width:min(520px,100%)}
.hint{color:var(--muted);font-size:12px}.count{color:var(--muted);font-size:12px;margin-left:auto}
.wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;background:var(--card);max-height:78vh}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;white-space:nowrap}
th{position:sticky;top:0;background:var(--card);text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none;font-weight:600}
th.num,td.num{text-align:right}th .s{opacity:.5;margin-left:3px;font-size:10px}
td{padding:3px 8px;border-bottom:1px solid var(--line);max-width:480px;overflow:hidden;text-overflow:ellipsis}
tr:nth-child(even) td{background:var(--zebra)}td.k{cursor:pointer}td.k:hover{text-decoration:underline}
mark{background:var(--hl);color:inherit;padding:0}
.more{padding:8px;color:var(--muted);text-align:center}
#chart{width:100%;height:160px;display:block}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted)}pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px;font-size:11px;overflow-x:auto}
</style></head><body><main>
<h1>__TITLE__ <small id="sub"></small></h1>
<div class="cards" id="cards"></div>
<svg id="chart"></svg>
<div class="tabs" id="tabs"></div>
<div class="bar"><input type="search" id="q" placeholder="search this table - space-separated terms must all match; prefix a term with - to exclude; col:value to target a column" autofocus>
<span class="hint" id="hint"></span><span class="count" id="count"></span></div>
<div class="wrap"><table id="t"></table></div>
<details><summary>How this was produced</summary><pre id="cmd"></pre></details>
</main>
<script>
const D=__DATA__; let cur=D.tables[0].id, sortCol=null, sortDir=-1;
const hp=new URLSearchParams(location.hash.slice(1)); if(hp.get("tab")&&D.tables.some(t=>t.id===hp.get("tab")))cur=hp.get("tab");
const $=i=>document.getElementById(i);
const fmt=(n,u="")=>{if(typeof n!=="number")return n;const a=Math.abs(n);if(a>=1e12)return (n/1e12).toFixed(1)+"T"+u;if(a>=1e9)return (n/1e9).toFixed(1)+"G"+u;if(a>=1e6)return (n/1e6).toFixed(1)+"M"+u;if(a>=1e3)return (n/1e3).toFixed(1)+"K"+u;return (Number.isInteger(n)?n:n.toFixed(1))+u};
const dur=s=>s<1?(s*1000).toFixed(0)+" ms":s<120?s.toFixed(1)+" s":s<7200?(s/60).toFixed(1)+" min":s<172800?(s/3600).toFixed(1)+" h":(s/86400).toFixed(1)+" d";
const esc=s=>String(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const m=D.meta;
$("sub").textContent=`${m.start_iso} → ${m.end_iso} UTC` + (m.filter?`   filter: ${m.filter}`:"");
$("cards").innerHTML=[["Packets",fmt(m.packets)],["Bytes",fmt(m.bytes,"B")],["Duration",dur(m.duration)],["Avg",fmt(m.packets/m.duration)+" pps"],
 ["MACs",fmt(m.counts.macs)],["IPs",fmt(m.counts.ips)],["Conversations",fmt(m.counts.conversations)],["Flows",fmt(m.counts.flows)],["Ports",fmt(m.counts.ports)],["DNS names",fmt(m.counts.dns)],["TLS SNI",fmt(m.counts.tls_sni)],["HTTP reqs",fmt(m.counts.http)]]
 .map(([k,v])=>`<div class="card"><b>${v}</b><span>${k}</span></div>`).join("");
$("cmd").textContent=D.cmd;
function tabs(){$("tabs").innerHTML=D.tables.map(t=>`<button class="${t.id===cur?"on":""}" data-id="${t.id}">${t.title}<i>${fmt(t.total)}</i></button>`).join("");
 $("tabs").querySelectorAll("button").forEach(b=>b.onclick=()=>{cur=b.dataset.id;sortCol=null;tabs();render()})}
function parse(q){const inc=[],exc=[],col=[];for(const w of q.toLowerCase().split(/\s+/).filter(Boolean)){
 if(w.startsWith("-")&&w.length>1)exc.push(w.slice(1));else if(w.includes(":")&&!/^[0-9a-f:]+$/.test(w)){const [c,...v]=w.split(":");col.push([c,v.join(":")])}else inc.push(w)}return {inc,exc,col}}
function render(){
 const T=D.tables.find(t=>t.id===cur), q=parse($("q").value);
 history.replaceState(null,"","#tab="+cur+($("q").value?"&q="+encodeURIComponent($("q").value):""));
 $("hint").textContent=T.hint;
 const cols=T.cols, lc=cols.map(c=>c.toLowerCase());
 let rows=T.rows;
 if(q.inc.length||q.exc.length||q.col.length){rows=rows.filter(r=>{const s=r.join("\u0001").toLowerCase();
  if(!q.inc.every(w=>s.includes(w)))return false; if(q.exc.some(w=>s.includes(w)))return false;
  return q.col.every(([c,v])=>{const i=lc.findIndex(x=>x.startsWith(c));return i>=0&&String(r[i]).toLowerCase().includes(v)})})}
 if(sortCol!==null){const i=sortCol;rows=[...rows].sort((a,b)=>{const x=a[i],y=b[i];return (typeof x==="number"&&typeof y==="number"?x-y:String(x).localeCompare(String(y)))*sortDir})}
 const cap=2000, shown=rows.slice(0,cap), numc=cols.map((c,i)=>T.rows.length&&typeof T.rows[0][i]==="number");
 const hl=s=>{s=esc(s);for(const w of q.inc)if(w)s=s.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),"ig"),x=>`<mark>${x}</mark>`);return s};
 $("t").innerHTML=`<thead><tr>${cols.map((c,i)=>`<th class="${numc[i]?"num":""}" data-i="${i}">${c}${sortCol===i?`<span class="s">${sortDir<0?"▼":"▲"}</span>`:""}</th>`).join("")}</tr></thead><tbody>`+
  shown.map(r=>`<tr>${r.map((v,i)=>`<td class="${numc[i]?"num":"k"}" title="${esc(v)}">${numc[i]?fmt(v):hl(v)}</td>`).join("")}</tr>`).join("")+`</tbody>`+
  (rows.length>cap?`<tfoot><tr><td class="more" colspan="${cols.length}">showing ${cap} of ${rows.length} matching rows - narrow the search, or open ${T.id}.csv for everything</td></tr></tfoot>`:"");
 $("count").textContent=`${rows.length.toLocaleString()} of ${T.rows.length.toLocaleString()} rows`+(T.total>T.rows.length?` (HTML capped at ${T.rows.length.toLocaleString()}; CSV has all ${T.total.toLocaleString()})`:"");
 $("t").querySelectorAll("th").forEach(h=>h.onclick=()=>{const i=+h.dataset.i;if(sortCol===i)sortDir=-sortDir;else{sortCol=i;sortDir=numc[i]?-1:1}render()});
 $("t").querySelectorAll("td.k").forEach(td=>td.onclick=()=>{const v=td.title.split(/\s+/)[0];if(v){$("q").value=v;render()}});
}
// mini histogram on top: click a bar to filter tables by nothing (it's context), hover shows time
(function(){const H=D.tables.find(t=>t.id==="histogram");if(!H||!H.rows.length)return;const svg=$("chart"),W=svg.clientWidth||1200,Ht=160,L=50,B=22;
 const fi=H.cols.indexOf("frames"),ti=H.cols.indexOf("t_iso"),ri=H.cols.indexOf("t_rel");const mx=Math.max(1,...H.rows.map(r=>r[fi]));const bw=(W-L-8)/H.rows.length;
 let s=`<text x="${L-4}" y="12" text-anchor="end" font-size="10" fill="var(--muted)">${fmt(mx)}</text><line x1="${L}" x2="${W-8}" y1="${Ht-B}" y2="${Ht-B}" stroke="var(--line)"/>`;
 H.rows.forEach((r,i)=>{const h=(r[fi]/mx)*(Ht-B-14);s+=`<rect x="${(L+i*bw).toFixed(1)}" y="${(Ht-B-h).toFixed(1)}" width="${Math.max(.5,bw-.8).toFixed(1)}" height="${h.toFixed(1)}" fill="var(--accent)"><title>${r[ti]}  t+${r[ri]}s\n${r[fi]} pkts</title></rect>`});
 const n=Math.max(2,Math.floor(W/140));for(let k=0;k<=n;k++){const i=Math.min(H.rows.length-1,Math.round(k*(H.rows.length-1)/n));s+=`<text x="${(L+i*bw+bw/2).toFixed(1)}" y="${Ht-6}" text-anchor="middle" font-size="10" fill="var(--muted)">${String(H.rows[i][ti]).slice(11,19)}</text>`}
 svg.innerHTML=s})();
$("q").value=hp.get("q")||"";$("q").oninput=render;tabs();render();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("-o", "--out", help="parent directory for <name>.report/ (default: next to the pcap)")
    ap.add_argument("-Y", "--filter", help="Wireshark display filter applied before everything")
    ap.add_argument("--bins", type=int, default=120, help="target histogram buckets (default 120)")
    ap.add_argument("--interval", type=float, help="histogram bucket seconds (overrides --bins)")
    ap.add_argument("--html-rows", type=int, default=20000, help="max rows per table embedded in HTML (default 20000)")
    ap.add_argument("--fast", action="store_true", help="disable TCP stream analysis/desegmentation (big captures)")
    ap.add_argument("--no-html", action="store_true")
    a = ap.parse_args()

    need("tshark"); need("capinfos")
    if not os.path.isfile(a.pcap):
        die(f"no such file: {a.pcap}")
    info = capinfos(a.pcap)
    if info["packets"] == 0:
        die("capture contains no packets")
    interval = a.interval or pick_interval(info["duration"], a.bins)

    cmd = ["tshark", "-n", "-r", a.pcap, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    if a.fast:
        cmd += ["-o", "tcp.analyze_sequence_numbers:FALSE", "-o", "tcp.desegment_tcp_streams:FALSE"]
    if a.filter:
        cmd += ["-Y", a.filter]
    for fld in FIELDS:
        cmd += ["-e", fld]
    sys.stderr.write(f"pcap_report: {info['packets']:,} packets, {info['duration']:.1f}s -> {interval}s buckets; "
                     f"streaming tshark...\n")
    rep = Report(interval, info["start"])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1 << 16)
    nf = len(FIELDS)
    for line in proc.stdout:
        f = line.rstrip("\n").split("\t")
        if len(f) != nf:
            rep.warn_lines += 1
            continue
        rep.packet(f)
        if rep.n % 500000 == 0:
            sys.stderr.write(f"  {rep.n:,} packets...\n")
    err = proc.stderr.read()
    if proc.wait() != 0:
        die(f"tshark failed:\n{err.strip()}")
    if rep.n == 0:
        die("no packets matched" + (f" filter {a.filter!r}" if a.filter else ""))
    if rep.warn_lines:
        sys.stderr.write(f"pcap_report: {rep.warn_lines} unparseable tshark lines skipped\n")

    base = os.path.splitext(os.path.basename(a.pcap))[0]
    parent = a.out or os.path.dirname(os.path.abspath(a.pcap))
    outdir = os.path.join(parent, base + ".report")
    os.makedirs(outdir, exist_ok=True)

    tables_json, counts = [], {}
    for stem, title, builder, hint in TABLES:
        cols, rows = getattr(rep, builder)()
        write_csv(os.path.join(outdir, stem + ".csv"), cols, rows)
        counts[stem] = len(rows)
        tables_json.append({"id": stem, "title": title, "hint": hint, "cols": cols,
                            "rows": rows[:a.html_rows], "total": len(rows)})
        sys.stderr.write(f"  {stem}.csv  {len(rows):,} rows\n")

    meta = {"source": os.path.basename(a.pcap), "file_type": info["file_type"], "packets": rep.n,
            "bytes": sum(c.by for c in rep.cols.values()), "duration": info["duration"],
            "start": info["start"], "end": info["end"], "start_iso": iso(info["start"]), "end_iso": iso(info["end"]),
            "filter": a.filter, "interval": interval, "counts": counts,
            "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tshark_cmd": " ".join(cmd)}
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        json.dump(meta, f, indent=2)

    if not a.no_html:
        data = {"meta": meta, "tables": tables_json, "cmd": " ".join(cmd)}
        html = (HTML.replace("__TITLE__", base + " — capture inventory")
                .replace("__DATA__", json.dumps(data, separators=(",", ":")).replace("</", "<\\/")))
        with open(os.path.join(outdir, "report.html"), "w") as f:
            f.write(html)
    sys.stderr.write(f"wrote {outdir}/\n")


if __name__ == "__main__":
    main()

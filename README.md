# LiteWork

Low-overhead pcap analysis, an homage to Wireshark built in Rust. LiteWork
**virtualizes** captures instead of loading them: one sequential pass builds a
tiny row-group index, every query prunes to the few file regions that can
match, and raw packet bytes are read from the mmap only when you look at them.
Works on captures of hundreds of GB on small laptops.

```
litework capture.pcap                 # interactive TUI
litework capture.pcap -p 5901 --ip.src 8.8.8.8   # TUI, pre-filtered
litework stats capture.pcap           # protocol mix, top MACs, ports, histogram
litework stats capture.pcap --json    # machine-readable
litework query capture.pcap 'mac == aa:bb:cc:dd:ee:ff && proto in {tcp, udp}'
litework query capture.pcap -P tcp -P udp -p 53 --json --limit 0
litework export capture.pcap out.pcap --ip 10.0.0.9   # save matches to a pcap
litework capture -i eth0 -w live.pcap             # live capture (Ctrl-C stops)
litework capture -i eth0 -w dns.pcap -p 53        # capture-time filtering
litework index capture.pcap           # index build timing / throughput
```

## Filter flags

Every command that filters also takes shorthand flags — no expression needed.
Different fields AND together; repeating a flag ORs within that field.

```
-p/--port  --sport --dport      -m/--mac  --mac.src --mac.dst
--ip  --ip.src --ip.dst         -P/--proto (tcp, udp, arp, ...)
--vlan                          -f/--filter '<raw expression>'
```

## Getting data out

- `litework export in.pcap out.pcap [flags|expr]` — matching packets to a new
  pcap (nanosecond precision, opens in Wireshark/tcpdump/LiteWork)
- In the TUI, `w` saves the current filter matches to `litework-export-<ts>.pcap`
- `litework query ... --json` — JSON lines for scripting; `stats --json` for
  whole-capture summaries

## Live capture

- `litework -i eth0` — **the TUI, live**: the packet list tails traffic
  (scroll up to pause following, `G` to resume), OVERVIEW/MACS/PORTS/FLOWS
  update in place, `/` filters apply to incoming packets in real time, and
  the header shows rate + kernel drops. **`Space` stops/resumes the capture**
  (header flips to ■ STOPPED) so you can freeze and dig in, then pick back up. Traffic spools to a temp pcap: on
  quit you choose save (with a filename prompt) or discard — or spool
  straight to a kept file with `-w out.pcap`. Filter flags pre-filter:
  `litework -i eth0 -p 53`
- `litework capture -i eth0 -w out.pcap` — headless capture to a pcap (live rate readout)
- `litework capture -i eth0` — **stream** packets to stdout as text lines
  (`--json` for JSON lines), tcpdump-style but with LiteWork filters:
  `litework capture -i eth0 -p 53 --ip '10.0.*'`
- `--seconds N` / `-c N` bound the run; no `-i` lists interfaces

Linux uses a pure-Rust AF_PACKET socket (needs root or CAP_NET_RAW); macOS
and Windows (runtime-loaded Npcap) arrive with M4.

## The .lwix sidecar (tier-1 index, opt-in)

A normal open writes nothing to disk. Pass `--index` (or run
`litework index <file>`) to persist the index as `capture.pcap.lwix` (~1-3%
of the capture): reopening becomes instant and every query/scroll runs off
lz4 columns without touching the pcap. An existing sidecar is always used
when valid and auto-invalidates when the capture changes; deleting it is
always safe.

- `--mem <MB>` caps RAM for decompressed columns (default 512)
- `--reindex` ignores/rebuilds an existing sidecar
- measured on a 945 MB / 15M-packet capture: build 2.7 s, reopen ~0 ms,
  full wildcard scan 0.5 s, RSS pinned to the `--mem` budget

## Filter language

Fields: `mac`, `mac_src`, `mac_dst`, `ip`, `ip_src`, `ip_dst`, `proto`,
`port`, `sport`, `dport`, `ethertype`, `vlan`, `len`
Operators: `==` `!=` `<` `>` `<=` `>=` `in {a, b, c}` `&&` `||` `!` `( )`
Protocols: any IANA protocol keyword (`tcp udp icmp gre ospf vrrp sctp ...`,
all 140), common ethertypes (`arp rarp lldp goose profinet mpls eapol ...`),
or a raw IP protocol number.

Service names come from the full IANA port registry (~6,100 named ports,
regenerable via `tools/gen_services.py`) with a curated overlay for
analyst-friendly names (`dns` not `domain`) and well-known unofficial ports
(`5901 vnc-1`, `4444 metasploit`, `51820 wireguard`).

Values can be **ranges and wildcards**, not just exact:

| kind          | examples                                          |
|---------------|---------------------------------------------------|
| port range    | `port == 5900-5910`, `port in {80, 443, 8000-8100}` |
| IP wildcard   | `ip == 10.10.*.180`, `ip == 10.10.*` (prefix)     |
| subnet (CIDR) | `ip == 192.168.1.0/24`, `ip == fe80::/10`         |
| MAC wildcard  | `mac == aa:bb:*:*:*:01`, `mac == aa:bb:*` (prefix)|

```
proto == tcp && dport == 443
ip == 10.10.*.180 && port == 5900-5910
ip_src == 192.168.1.0/24 && !(proto == arp)
mac == de:ad:be:*
len > 1200 && proto in {tcp, udp}
```

The same values work in the shorthand flags (quote `*` for your shell):
`litework cap.pcap -p 5000-5050 --ip '10.10.*' -P tcp`

## TUI

- `1` OVERVIEW — traffic histogram, protocol mix, top MACs, top ports
- `2` PACKETS — virtual-scrolling packet list; `/` opens a filter bar with
  **Wireshark-style completion** (fields → operators → values drawn from the
  capture's own MACs/IPs/ports; `Tab` completes, `?` shows the full syntax
  reference), `Enter` opens the dissection + hex/ASCII detail pane (`+`/`-`
  scroll), `w` saves matches to a pcap, `g`/`G` first/last, `Esc` clears
- `3` MACS — per-MAC totals (**as src / as dst / total**, bytes, protocol
  set, last seen); `v` switches to **mac_src → mac_dst flows**; `Enter` pivots
- `4` PORTS — **sport → dport pairs** by default (spot scans and services at
  a glance); `v` switches to single-port totals; `Enter` pivots
- `5` FLOWS — IP⇄IP conversations (pkts, bytes, protocols, ports, span);
  `Enter` pivots to that conversation's packets

**When a filter is active, MACS/PORTS/FLOWS aggregate only the matching
traffic** (titles show the filter), and pivots compose with it — filter to
`port == 5000-5999`, open MACS, and you see exactly which devices are in that
traffic. `?` opens the filter syntax reference from any tab.

Unknown protocols always degrade to the raw hex/ASCII view — every byte of
every packet is reachable.

## Install

- **Linux (any distro)**: grab `litework-*-linux-x86_64-static.tar.gz` from a
  release — a fully static binary with zero dependencies. Or build one with
  `tools/release.sh`.
- **From source (all platforms)**: `cargo install --path crates/litework`
  or `cargo build --release`. Windows and macOS build clean; live capture on
  those platforms arrives with M4 (file analysis is fully supported today).
- Live capture on Linux needs root or:
  `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v litework)`

Dual-licensed MIT / Apache-2.0.

## Mouse

The TUI is fully mouse-aware: scroll wheel everywhere (packet list, tables,
hex dump), click a tab to switch, click a row to select it, click again to
pivot/open detail, click the filter bar to edit. Your terminal's own
select-to-copy still works via shift+drag (bypasses mouse capture).

## Design

- `crates/litework-core` — formats (pcap + pcapng, any endianness, usec/nsec),
  dissection (L2–L4, lax), tier-0 row-group index (MAC sets, ethertype sets,
  IP-proto bitsets, port/IP blooms per 64K packets), filter engine with
  conservative group pruning (never a false negative — verified against brute
  force in tests)
- `crates/litework-capture` — live capture sources (M4: AF_PACKET / BPF /
  runtime-loaded Npcap)
- `crates/litework` — CLI + ratatui TUI

Memory stays flat while indexing (madvise drop-behind): ~1 GB/s and <20 MB RSS
on a 945 MB capture. The capture itself is never copied into memory.

## Roadmap

- M3: on-disk tier-1 columnar sidecar (background build, resumable), MACS /
  FLOWS / HIST tabs, `--mem` ceiling with LRU
- M4: finish live capture (macOS /dev/bpf, Windows Npcap runtime; Linux ships now)
- M5: L7 identity metadata (DNS qname, TLS SNI/JA4, HTTP host, DHCP hostname),
  release packaging (musl static, Windows zip, cargo-dist)

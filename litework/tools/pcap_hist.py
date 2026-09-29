#!/usr/bin/env python3
"""
pcap_hist.py - time histogram of a pcap/pcapng, built on tshark's io,stat.

Outputs (for input  foo.pcap):
  foo.hist.csv   one row per time bucket, one column per series  (always)
  foo.hist.html  self-contained interactive chart, no internet needed (default)
  terminal       quick ASCII sparkline + summary                    (default)

Why tshark -z io,stat:  it is the same engine Wireshark's Statistics > I/O Graphs
uses, it streams (works on any size capture; memory does not grow with file size
the way loading packets into Python would), and every series is a plain Wireshark
display filter, so anything you chart here you can immediately pivot on in
Wireshark / tshark with the same expression.

Dependencies: tshark + capinfos (Wireshark CLI tools). Python 3.8+, stdlib only.

Examples:
  pcap_hist.py capture.pcap                      # ~120 buckets, auto interval
  pcap_hist.py capture.pcap --interval 1         # fixed 1-second buckets
  pcap_hist.py capture.pcap --bins 300 -o out/   # more resolution, outputs in out/
  pcap_hist.py capture.pcap -Y "ip.addr==10.0.0.5"       # pre-filter everything
  pcap_hist.py capture.pcap --series "rdp=tcp.port==3389" # add your own series
  pcap_hist.py big.pcap --fast --no-html         # 50 GB file, CSV only
"""
import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys

# (name, Wireshark display filter, kind).  Order = column order in CSV and legend.
# kind "stack": mutually exclusive buckets that add up to the total -> stacked bars.
# kind "line":  overlapping views (tls is inside tcp, dns inside udp...) -> lines.
DEFAULT_SERIES = [
    ("tcp",   "tcp",                                   "stack"),
    ("udp",   "udp",                                   "stack"),
    ("icmp",  "icmp || icmpv6",                        "stack"),
    ("arp",   "arp",                                   "stack"),
    ("other", "!(tcp || udp || icmp || icmpv6 || arp)", "stack"),
    ("ipv6",  "ipv6",                                  "line"),
    ("dns",   "dns",                                   "line"),
    ("tls",   "tls",                                   "line"),
    ("http",  "http",                                  "line"),
    ("ssh",   "ssh",                                   "line"),
    ("smb",   "smb || smb2",                           "line"),
]


def die(msg):
    sys.stderr.write(f"pcap_hist: {msg}\n")
    sys.exit(1)


def need(tool):
    if shutil.which(tool) is None:
        die(f"'{tool}' not found - install Wireshark CLI tools (apt install tshark / brew install wireshark)")


def capinfos(path):
    """Return (packets, bytes, duration_s, start_epoch, end_epoch)."""
    out = subprocess.run(
        ["capinfos", "-T", "-m", "-r", "-a", "-e", "-c", "-d", "-u", "-S", path],
        capture_output=True, text=True)
    if out.returncode != 0:
        die(f"capinfos failed: {out.stderr.strip()}")
    row = next(csv.reader([out.stdout.strip().splitlines()[-1]]))
    # name, packets, bytes, duration, start, end
    try:
        return int(row[1]), int(row[2]), float(row[3]), float(row[4]), float(row[5])
    except (ValueError, IndexError):
        die(f"could not parse capinfos output: {out.stdout!r}")


def first_packet_epoch(path):
    """io,stat measures from the first packet in *file order* (not the earliest
    timestamp), so that is what absolute bucket times must be based on."""
    out = subprocess.run(["tshark", "-n", "-r", path, "-c", "1", "-T", "fields", "-e", "frame.time_epoch"],
                         capture_output=True, text=True)
    try:
        return float(out.stdout.strip().splitlines()[0])
    except (ValueError, IndexError):
        die(f"could not read first packet time: {out.stderr.strip()}")


def pick_interval(duration, bins):
    """Smallest 'nice' interval giving <= bins buckets."""
    nice = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30,
            60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400]
    raw = max(duration, 0.001) / max(bins, 1)
    for n in nice:
        if n >= raw:
            return n
    return nice[-1]


ROW_RE = re.compile(r"^\|\s*([\d.]+)\s*<>\s*([\d.]+|Dur)\s*\|(.*)\|\s*$")


def run_iostat(path, interval, series, display_filter, fast):
    # FRAMES()/BYTES() rather than COUNT(frame)/SUM(frame.len): the latter pair
    # silently returns zeros in tshark 4.x when the same field is used in
    # several columns.
    cols = ["FRAMES()frame", "BYTES()frame"]
    for _, flt, _k in series:
        cols.append(f"FRAMES(){flt}")
        cols.append(f"BYTES(){flt}")
    cmd = ["tshark", "-n", "-q", "-r", path]
    if fast:
        # big-capture mode: skip the stateful TCP bookkeeping that makes
        # tshark's memory grow with the number of conversations.
        cmd += ["-o", "tcp.analyze_sequence_numbers:FALSE",
                "-o", "tcp.desegment_tcp_streams:FALSE"]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-z", "io,stat," + ",".join([str(interval)] + cols)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        die(f"tshark failed:\n{proc.stderr.strip()}")
    rows = []
    for line in proc.stdout.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        start = float(m.group(1))
        cells = [c.strip() for c in m.group(3).split("|")]
        try:
            vals = [int(c) for c in cells if c != ""]
        except ValueError:
            continue
        if len(vals) != len(cols):
            continue
        rows.append((start, vals))
    if not rows:
        die("tshark produced no io,stat rows (empty capture or filter matched nothing?)\n"
            + proc.stdout[-2000:])
    return cmd, rows


def build_table(rows, interval, start_epoch, series):
    """-> list of dicts, one per bucket, with absolute time + all series."""
    names = ["frames", "bytes"]
    for n, _f, _k in series:
        names += [f"{n}_frames", f"{n}_bytes"]
    table = []
    for rel, vals in rows:
        t = start_epoch + rel
        rec = {
            "t_rel": round(rel, 6),
            "t_epoch": round(t, 6),
            "t_iso": dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="milliseconds"),
        }
        rec.update(zip(names, vals))
        rec["bits_per_s"] = round(rec["bytes"] * 8 / interval, 3)
        rec["frames_per_s"] = round(rec["frames"] / interval, 3)
        table.append(rec)
    return table


def write_csv(path, table, interval, meta):
    fields = list(table[0].keys())
    with open(path, "w", newline="") as f:
        # a few '#' comment lines first - every spreadsheet/pandas/duckdb reader
        # can skip them (comment='#') and they make the file self-describing.
        f.write(f"# source={meta['source']}\n")
        f.write(f"# interval_seconds={interval}\n")
        f.write(f"# display_filter={meta['display_filter'] or ''}\n")
        f.write(f"# generated={dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}\n")
        f.write("# times are UTC; t_rel is seconds since first packet; *_frames/*_bytes are per bucket\n")
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in table:
            w.writerow(r)


def human(n, unit=""):
    for s in ["", "K", "M", "G", "T"]:
        if abs(n) < 1000:
            return f"{n:.1f}{s}{unit}" if s else f"{n:.0f}{unit}"
        n /= 1000
    return f"{n:.1f}P{unit}"


def fmt_dur(s):
    if s < 1:
        return f"{s*1000:.0f} ms"
    if s < 120:
        return f"{s:.1f} s"
    if s < 7200:
        return f"{s/60:.1f} min"
    if s < 172800:
        return f"{s/3600:.1f} h"
    return f"{s/86400:.1f} d"


def terminal_chart(table, interval, meta, series, width=None):
    width = width or min(shutil.get_terminal_size((100, 20)).columns, 120)
    blocks = " ▁▂▃▄▅▆▇█"
    frames = [r["frames"] for r in table]
    mx = max(frames) or 1
    # fold buckets down to terminal width
    n = len(frames)
    fold = max(1, -(-n // width))
    folded = [max(frames[i:i + fold]) for i in range(0, n, fold)]
    import math
    lin = "".join(blocks[min(8, int(v / mx * 8 + (0.999 if v else 0)))] for v in folded)
    lmx = math.log10(mx + 1)
    lg = "".join(blocks[min(8, int(math.log10(v + 1) / lmx * 8 + (0.999 if v else 0)))] for v in folded)
    p, b, d = meta["packets"], meta["bytes"], meta["duration"]
    peak_i = frames.index(max(frames))
    peak = table[peak_i]
    print(f"{meta['source']}: {human(p)} pkts, {human(b, 'B')}, {fmt_dur(d)}, "
          f"{human(p/d if d else 0)} pps avg, {human(b*8/d if d else 0, 'bps')} avg")
    print(f"buckets: {n} x {interval}s   peak: {human(peak['frames'])} pkts @ "
          f"{peak['t_iso']} (t_rel={peak['t_rel']}s)")
    print(f"linear {lin}")
    print(f"log    {lg}")
    tot = {n_: sum(r[f'{n_}_frames'] for r in table) for n_, _f, _k in series}
    mix = "  ".join(f"{k} {100*v/p:.0f}%" for k, v in sorted(tot.items(), key=lambda kv: -kv[1]) if v)
    print(f"mix: {mix}")


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#fafafa;--fg:#1c1c1e;--muted:#6b6b72;--line:#e2e2e6;--card:#fff;--accent:#2f6fed;--sel:rgba(47,111,237,.15)}
@media(prefers-color-scheme:dark){:root{--bg:#121214;--fg:#ececf0;--muted:#9a9aa4;--line:#2a2a30;--card:#1b1b1f;--accent:#6b9cff;--sel:rgba(107,156,255,.2)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1400px;margin:0 auto;padding:20px}
h1{font-size:18px;margin:0 0 2px;font-weight:600}h1 small{color:var(--muted);font-weight:400;margin-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:20px;font-weight:600}.card span{color:var(--muted);font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;margin:8px 0;font-size:13px}
.bar label{display:inline-flex;align-items:center;gap:5px;cursor:pointer;user-select:none}
.sw{width:12px;height:12px;border-radius:3px;display:inline-block}
button,select{font:inherit;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 9px;cursor:pointer}
button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.wrap{position:relative;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px}
svg{width:100%;height:420px;display:block;cursor:crosshair}
.tip{position:absolute;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:12px;box-shadow:0 4px 16px rgba(0,0,0,.18);display:none;min-width:220px;z-index:2}
.tip table{border-collapse:collapse}.tip td{padding:1px 6px 1px 0}.tip td:last-child{text-align:right;font-variant-numeric:tabular-nums}
.tip code{display:block;margin-top:6px;color:var(--muted);font-size:11px;word-break:break-all}
.hint{color:var(--muted);font-size:12px;margin:8px 0 0}
details{margin-top:14px}summary{cursor:pointer;color:var(--muted)}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;font-size:12px}
table.mix{border-collapse:collapse;margin-top:6px;font-size:13px}table.mix td,table.mix th{padding:3px 10px 3px 0;text-align:left}
table.mix td:nth-child(n+3),table.mix th:nth-child(n+3){text-align:right;font-variant-numeric:tabular-nums}
.mixbar{height:8px;background:var(--accent);border-radius:2px;display:inline-block;vertical-align:middle}
</style></head><body><main>
<h1>__TITLE__ <small id="sub"></small></h1>
<div class="cards" id="cards"></div>
<div class="bar">
  <span>Metric:</span>
  <button id="mFrames" class="on">packets</button><button id="mBytes">bytes</button>
  <span style="margin-left:10px">Scale:</span>
  <button id="sLin" class="on">linear</button><button id="sLog">log</button>
  <span style="margin-left:10px">View:</span>
  <button id="vStack" class="on">stacked by transport</button><button id="vTotal">total only</button>
  <button id="reset" style="margin-left:auto">reset zoom</button>
</div>
<div class="bar" id="legend"></div>
<div class="wrap"><svg id="chart"></svg><div class="tip" id="tip"></div></div>
<p class="hint">Hover a bar for detail. Drag to zoom into a time range. Each tooltip shows the Wireshark display filter that selects exactly that bucket - paste it into Wireshark or <code>tshark -Y</code> to pull those packets.</p>
<div id="mix"></div>
<details><summary>How this was produced</summary><pre id="cmd"></pre></details>
</main>
<script>
const D = __DATA__;
const PAL = ["#2f6fed","#e4572e","#17a398","#f4b942","#8e5fd6","#3cb44b","#e6194b","#46c0e6","#a0522d","#808000","#9a9aa4"];
const series = D.series.map((s,i)=>({name:s[0], filter:s[1], kind:s[2], color:PAL[i%PAL.length], on:true}));
const rows = D.rows, iv = D.interval;
let metric="frames", log=false, stacked=true, view=[0, rows.length];
const $ = id=>document.getElementById(id);
const fmt = (n,u="")=>{const a=Math.abs(n);if(a>=1e12)return (n/1e12).toFixed(1)+"T"+u;if(a>=1e9)return (n/1e9).toFixed(1)+"G"+u;if(a>=1e6)return (n/1e6).toFixed(1)+"M"+u;if(a>=1e3)return (n/1e3).toFixed(1)+"K"+u;return (Number.isInteger(n)?n:n.toFixed(1))+u};
const dur = s=>s<1?(s*1000).toFixed(0)+" ms":s<120?s.toFixed(1)+" s":s<7200?(s/60).toFixed(1)+" min":s<172800?(s/3600).toFixed(1)+" h":(s/86400).toFixed(1)+" d";
const tfmt = e=>{const d=new Date(e*1000);return d.toISOString().replace("T"," ").replace("Z","").slice(0,23)};

function cards(){
  const m=D.meta, pk=rows.reduce((a,r)=>r.frames>a.frames?r:a,rows[0]);
  const c=[["Packets",fmt(m.packets)],["Bytes",fmt(m.bytes,"B")],["Duration",dur(m.duration)],
    ["Avg rate",fmt(m.packets/m.duration)+" pps"],["Avg throughput",fmt(m.bytes*8/m.duration,"bps")],
    ["Peak bucket",fmt(pk.frames)+" pkts @ t+"+pk.t_rel+"s"],["Buckets",rows.length+" × "+iv+" s"]];
  $("cards").innerHTML=c.map(([k,v])=>`<div class="card"><b>${v}</b><span>${k}</span></div>`).join("");
  $("sub").textContent=tfmt(m.start)+" → "+tfmt(m.end)+" UTC"+(m.display_filter?"   filter: "+m.display_filter:"");
}
function legend(){
  const item=(s,i)=>`<label><input type="checkbox" data-i="${i}" ${s.on?"checked":""} hidden><span class="sw" style="background:${s.color};opacity:${s.on?1:.25};${s.kind==="line"?"height:3px;border-radius:0":""}"></span>${s.name}</label>`;
  const st=series.map((s,i)=>[s,i]).filter(x=>x[0].kind==="stack"), ln=series.map((s,i)=>[s,i]).filter(x=>x[0].kind==="line");
  $("legend").innerHTML="<span>Bars:</span>"+st.map(x=>item(...x)).join("")+"<span style=\"margin-left:14px\">Lines:</span>"+ln.map(x=>item(...x)).join("");
  $("legend").querySelectorAll("input").forEach(el=>el.onchange=()=>{series[el.dataset.i].on=el.checked;legend();draw()});
}
function mixTable(){
  const tot=series.map(s=>({n:s.name,f:rows.reduce((a,r)=>a+r[s.name+"_frames"],0),b:rows.reduce((a,r)=>a+r[s.name+"_bytes"],0),flt:s.filter})).sort((a,b)=>b.f-a.f);
  const P=D.meta.packets||1,B=D.meta.bytes||1;
  $("mix").innerHTML=`<table class="mix"><tr><th>series</th><th>filter</th><th>packets</th><th>% pkts</th><th>bytes</th><th>% bytes</th><th></th></tr>`+
    tot.map(t=>`<tr><td>${t.n}</td><td><code>${t.flt}</code></td><td>${fmt(t.f)}</td><td>${(100*t.f/P).toFixed(1)}%</td><td>${fmt(t.b,"B")}</td><td>${(100*t.b/B).toFixed(1)}%</td><td><span class="mixbar" style="width:${Math.max(1,120*t.f/P)}px"></span></td></tr>`).join("")+"</table>";
}
function val(r,s){return r[(s?s+"_":"")+metric]}

const svg=$("chart"), tip=$("tip"), NS="http://www.w3.org/2000/svg";
function el(n,a){const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);return e}
let drag=null;
function draw(){
  svg.innerHTML="";
  const W=svg.clientWidth,H=svg.clientHeight,L=64,R=12,T=14,Bm=46;
  const vis=rows.slice(view[0],view[1]); if(!vis.length)return;
  const on=series.filter(s=>s.on), onS=on.filter(s=>s.kind==="stack"), onL=on.filter(s=>s.kind==="line");
  const tops=vis.map(r=>Math.max(stacked&&!log?onS.reduce((a,s)=>a+val(r,s.name),0):val(r,null), ...onL.map(s=>val(r,s.name))));
  const mx=Math.max(1,...tops);
  const y=v=>{if(log){return H-Bm-(Math.log10(v+1)/Math.log10(mx+1))*(H-T-Bm)}return H-Bm-(v/mx)*(H-T-Bm)};
  const bw=(W-L-R)/vis.length, x=i=>L+i*bw;
  // gridlines
  const ticks=log?[...Array(Math.ceil(Math.log10(mx+1))+1).keys()].map(k=>Math.pow(10,k)-1):[0,.25,.5,.75,1].map(f=>f*mx);
  for(const tv of ticks){if(tv>mx)continue;const yy=y(tv);svg.appendChild(el("line",{x1:L,x2:W-R,y1:yy,y2:yy,stroke:"var(--line)"}));
    const t=el("text",{x:L-6,y:yy+4,"text-anchor":"end","font-size":11,fill:"var(--muted)"});t.textContent=fmt(tv,metric==="bytes"?"B":"");svg.appendChild(t)}
  // bars
  const g=el("g",{});
  vis.forEach((r,i)=>{
    let base=0;
    // stacking is only meaningful on a linear axis; log mode shows the total bar
    const segs=stacked&&!log?onS.map(s=>[val(r,s.name),s.color]):[[val(r,null),"var(--accent)"]];
    for(const [v,c] of segs){ if(!v)continue;
      const y0=y(base+v), y1=y(base);
      g.appendChild(el("rect",{x:x(i)+0.5,y:y0,width:Math.max(0.5,bw-1),height:Math.max(0,y1-y0),fill:c}));
      base+=v; }
  });
  svg.appendChild(g);
  for(const s of onL){
    const pts=vis.map((r,i)=>(x(i)+bw/2).toFixed(1)+","+y(val(r,s.name)).toFixed(1)).join(" ");
    svg.appendChild(el("polyline",{points:pts,fill:"none",stroke:s.color,"stroke-width":2,"stroke-linejoin":"round"}));
  }
  // x labels
  const nl=Math.max(2,Math.floor((W-L-R)/110));
  for(let k=0;k<=nl;k++){const i=Math.min(vis.length-1,Math.round(k*(vis.length-1)/nl));const xx=x(i)+bw/2;
    const t=el("text",{x:xx,y:H-Bm+16,"text-anchor":"middle","font-size":11,fill:"var(--muted)"});t.textContent=tfmt(vis[i].t_epoch).slice(11,19);svg.appendChild(t);
    const t2=el("text",{x:xx,y:H-Bm+30,"text-anchor":"middle","font-size":10,fill:"var(--muted)"});t2.textContent="t+"+vis[i].t_rel+"s";svg.appendChild(t2)}
  const axis=el("line",{x1:L,x2:W-R,y1:H-Bm,y2:H-Bm,stroke:"var(--muted)"});svg.appendChild(axis);
  // hover + drag
  const hov=el("rect",{x:0,y:T,width:0,height:H-T-Bm,fill:"var(--sel)",style:"display:none"});svg.appendChild(hov);
  const sel=el("rect",{x:0,y:T,width:0,height:H-T-Bm,fill:"var(--sel)",stroke:"var(--accent)","stroke-dasharray":"3 3",style:"display:none"});svg.appendChild(sel);
  const idxAt=ev=>{const b=svg.getBoundingClientRect();return Math.max(0,Math.min(vis.length-1,Math.floor((ev.clientX-b.left-L)/bw)))};
  svg.onmousemove=ev=>{const i=idxAt(ev);const r=vis[i];
    hov.style.display="";hov.setAttribute("x",x(i));hov.setAttribute("width",bw);
    if(drag){const a=Math.min(drag,i),b=Math.max(drag,i);sel.style.display="";sel.setAttribute("x",x(a));sel.setAttribute("width",(b-a+1)*bw);return}
    const lines=on.map(s=>`<tr><td><span class="sw" style="background:${s.color};${s.kind==="line"?"height:3px;border-radius:0":""}"></span> ${s.name}</td><td>${fmt(r[s.name+"_frames"])} pkts</td><td>${fmt(r[s.name+"_bytes"],"B")}</td></tr>`).join("");
    const t0=r.t_rel, t1=+(r.t_rel+iv).toFixed(6);
    tip.innerHTML=`<b>${tfmt(r.t_epoch)}</b> &nbsp;<span style="color:var(--muted)">t+${t0}s, ${iv}s bucket</span>
      <table><tr><td><b>total</b></td><td><b>${fmt(r.frames)} pkts</b></td><td><b>${fmt(r.bytes,"B")}</b></td></tr>
      <tr><td>rate</td><td>${fmt(r.frames_per_s)} pps</td><td>${fmt(r.bits_per_s,"bps")}</td></tr>${lines}</table>
      <code>frame.time_relative >= ${t0} && frame.time_relative < ${t1}</code>`;
    tip.style.display="block";const b=svg.getBoundingClientRect();
    const tx=ev.clientX-b.left+14, ty=ev.clientY-b.top+14;
    tip.style.left=Math.min(tx,W-tip.offsetWidth-10)+"px";tip.style.top=Math.min(ty,H-tip.offsetHeight-10)+"px";
  };
  svg.onmouseleave=()=>{tip.style.display="none";hov.style.display="none"};
  svg.onmousedown=ev=>{drag=idxAt(ev);tip.style.display="none"};
  svg.onmouseup=ev=>{if(drag==null)return;const i=idxAt(ev);const a=Math.min(drag,i),b=Math.max(drag,i);drag=null;sel.style.display="none";
    if(b-a>=1){view=[view[0]+a,view[0]+b+1];draw()}};
}
function tog(a,b,cb){$(a).onclick=()=>{cb(true);$(a).classList.add("on");$(b).classList.remove("on");draw()};$(b).onclick=()=>{cb(false);$(b).classList.add("on");$(a).classList.remove("on");draw()}}
tog("mFrames","mBytes",v=>metric=v?"frames":"bytes");
tog("sLin","sLog",v=>log=!v);
tog("vStack","vTotal",v=>stacked=v);
$("reset").onclick=()=>{view=[0,rows.length];draw()};
$("cmd").textContent=D.cmd+"\n\n# pull the packets for any bucket:\ntshark -r "+D.meta.source+" -Y 'frame.time_relative >= START && frame.time_relative < END'";
cards();legend();mixTable();draw();
addEventListener("resize",draw);
</script></body></html>
"""


def write_html(path, table, interval, meta, series, cmd):
    data = {
        "interval": interval,
        "series": [[n, f, k] for n, f, k in series],
        "rows": table,
        "meta": {
            "source": os.path.basename(meta["source"]),
            "packets": meta["packets"], "bytes": meta["bytes"], "duration": meta["duration"],
            "start": meta["start"], "end": meta["end"], "display_filter": meta["display_filter"],
        },
        "cmd": " ".join(repr(c) if " " in c or "(" in c else c for c in cmd),
    }
    html = (HTML_TEMPLATE
            .replace("__TITLE__", os.path.basename(meta["source"]) + " — traffic histogram")
            .replace("__DATA__", json.dumps(data).replace("</", "<\\/")))
    with open(path, "w") as f:
        f.write(html)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--bins", type=int, default=120, help="target number of buckets (default 120)")
    ap.add_argument("--interval", type=float, help="bucket width in seconds (overrides --bins)")
    ap.add_argument("-o", "--out", help="output path prefix or directory (default: next to the pcap)")
    ap.add_argument("-Y", "--filter", help="Wireshark display filter applied before bucketing")
    ap.add_argument("--series", action="append", default=[], metavar="NAME=FILTER",
                    help="add a series drawn as a line, e.g. --series 'rdp=tcp.port==3389' (repeatable)")
    ap.add_argument("--only-series", action="append", default=[], metavar="NAME=FILTER",
                    help="like --series but replaces the default set")
    ap.add_argument("--fast", action="store_true", help="disable TCP stream analysis (use for very large captures)")
    ap.add_argument("--no-html", action="store_true")
    ap.add_argument("--no-term", action="store_true", help="skip the terminal chart")
    a = ap.parse_args()

    need("tshark"); need("capinfos")
    if not os.path.isfile(a.pcap):
        die(f"no such file: {a.pcap}")

    def parse_series(items):
        out = []
        for s in items:
            if "=" not in s:
                die(f"--series needs NAME=FILTER, got {s!r}")
            n, f = s.split("=", 1)
            n = re.sub(r"[^A-Za-z0-9_]", "_", n.strip())
            if "," in f:
                die(f"series {n!r}: io,stat filters cannot contain commas (tshark splits on them). "
                    f"Write  tcp.port==80 || tcp.port==443  instead of  tcp.port in {{80,443}}")
            out.append((n, f.strip(), "line"))
        return out
    series = parse_series(a.only_series) if a.only_series else DEFAULT_SERIES + parse_series(a.series)

    packets, nbytes, duration, start, end = capinfos(a.pcap)
    if packets == 0:
        die("capture contains no packets")
    first = first_packet_epoch(a.pcap)
    if abs(first - start) > 1e-6:
        sys.stderr.write(f"pcap_hist: WARNING capture is not in time order (first packet is "
                         f"{first - start:.3f}s after the earliest). Buckets are relative to the first "
                         f"packet, as tshark does; run `reordercap in.pcap out.pcap` for exact results.\n")
        start = first
        duration = end - first
    interval = a.interval or pick_interval(duration, a.bins)
    sys.stderr.write(f"pcap_hist: {human(packets)} packets over {fmt_dur(duration)} -> {interval}s buckets, "
                     f"{len(series)} series; running tshark...\n")

    cmd, rows = run_iostat(a.pcap, interval, series, a.filter, a.fast)
    table = build_table(rows, interval, start, series)
    meta = {"source": a.pcap, "packets": packets, "bytes": nbytes, "duration": duration,
            "start": start, "end": end, "display_filter": a.filter}
    if a.filter:  # summary cards should reflect what was actually charted
        meta["packets"] = sum(r["frames"] for r in table)
        meta["bytes"] = sum(r["bytes"] for r in table)

    base = os.path.splitext(os.path.basename(a.pcap))[0]
    if a.out and (os.path.isdir(a.out) or a.out.endswith(os.sep)):
        os.makedirs(a.out, exist_ok=True)
        prefix = os.path.join(a.out, base)
    elif a.out:
        prefix = a.out
    else:
        prefix = os.path.join(os.path.dirname(os.path.abspath(a.pcap)), base)

    csv_path = prefix + ".hist.csv"
    write_csv(csv_path, table, interval, meta)
    written = [csv_path]
    if not a.no_html:
        html_path = prefix + ".hist.html"
        write_html(html_path, table, interval, meta, series, cmd)
        written.append(html_path)
    if not a.no_term:
        terminal_chart(table, interval, meta, series)
    for w in written:
        sys.stderr.write(f"wrote {w}\n")


if __name__ == "__main__":
    main()

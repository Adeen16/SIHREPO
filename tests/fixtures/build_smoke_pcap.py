"""
tests/fixtures/build_smoke_pcap.py
-----------------------------------
FUNCTIONAL TEST ONLY - hand-built to verify plumbing, not a performance
benchmark, not training data.

Builds tests/fixtures/smoke_attack.pcap containing two synthetic packet
sequences designed to trip the behavioral detection thresholds:

1. DDoS sequence:
   - 60 distinct source IPs each send 120 packets to 10.0.0.1:80
   - All packets within a 5-second window
   - Expected triggers:
       is_concentrated : flows_to_dst=60 > 50, unique_src=60 > 20 → +2 signals
       is_burst        : packets_to_dst=7200 > 2000, flows=60 > 5 → +2 signals
       is_high_volume  : 7200 pkts in 5s → 1440 pps > 1000 → +1 signal
   - Total signals = 5 >= threshold of 3 → DETECTED

2. Recon / port-scan sequence:
   - 1 source IP (192.168.1.200) sends 1 SYN to each of 60 distinct ports
     on a single target (192.168.1.1)
   - Expected trigger:
       src_ip_unique_dst_ports = 60 >= 50, unique_dst_ips = 1 <= 10 → DETECTED

All packets are hand-crafted and completely synthetic.
This fixture is NOT real traffic; it MUST NOT be used for training.
"""

import pathlib, sys

try:
    from scapy.all import (
        Ether, IP, TCP, wrpcap, conf
    )
except ImportError:
    sys.exit("scapy not installed — run: pip install scapy")

conf.verb = 0  # silence scapy

OUT = pathlib.Path("tests/fixtures/smoke_attack.pcap")
OUT.parent.mkdir(parents=True, exist_ok=True)

packets = []

# ── 1. DDoS flood: 60 sources × 120 pkts → 10.0.0.1:80 in 5s ────────────
base_ts = 1_700_000_000.0
window_s = 5.0
n_src    = 60
pkt_per_src = 120  # total = 7200 packets; 7200/5s = 1440 pps

for src_idx in range(n_src):
    src_ip  = f"192.168.{src_idx // 256}.{src_idx % 256}"
    src_port = 40000 + src_idx
    for pkt_idx in range(pkt_per_src):
        ts = base_ts + (pkt_idx / pkt_per_src) * window_s  # spread across 5s
        p = (
            Ether() /
            IP(src=src_ip, dst="10.0.0.1") /
            TCP(sport=src_port, dport=80, flags="S")
        )
        p.time = ts
        packets.append(p)

# ── 2. Recon port scan: 192.168.1.200 → 60 distinct ports on 192.168.1.1 ─
# Must fall in a different window offset (recon packets start after DDoS window)
recon_base = base_ts + window_s + 0.5  # 0.5s after DDoS window closes

for port_idx in range(60):
    ts = recon_base + port_idx * 0.01  # 10ms apart
    p = (
        Ether() /
        IP(src="192.168.1.200", dst="192.168.1.1") /
        TCP(sport=50000 + port_idx, dport=1 + port_idx, flags="S")
    )
    p.time = ts
    packets.append(p)

# Sort all packets by timestamp before writing
packets.sort(key=lambda p: float(p.time))

wrpcap(str(OUT), packets)
print(f"Written {len(packets)} packets to {OUT}")
print(f"  DDoS  segment: {n_src} sources x {pkt_per_src} pkt each = {n_src*pkt_per_src} pkt")
print(f"  Recon segment: 1 source, 60 distinct dst ports")

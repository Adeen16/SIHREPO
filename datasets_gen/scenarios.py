"""
datasets_gen/scenarios.py
--------------------------
Individual traffic scenario generators.

PASSIVE SAFETY: all scenarios produce lists of Scapy packets in memory.
No function here transmits packets. Output is passed to the writer module.

Each scenario returns:
  (packets: List[Packet], label_intervals: List[dict])

label_intervals format:
  {"threat": <str>, "src_ip": <str>, "dst_ip": <str|None>,
   "start_ts": <float>, "end_ts": <float>}
"""
from __future__ import annotations
import math
import random
import string
from typing import List, Tuple, Optional

from datasets_gen.addresses import (
    internal_host, external_host, botnet_source,
    random_internal, random_external, random_botnet,
)
from datasets_gen.packet_builder import (
    build_tcp_syn, build_tcp_synack, build_tcp_fin, build_tcp_rst,
    build_tcp_data, build_udp, build_icmp_echo,
    build_dns_query, build_dns_response,
)

Packets = list
Labels = list


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tcp_handshake(src, dst, sport, dport, ts):
    """Return SYN, SYN-ACK, ACK packets for a TCP handshake."""
    return [
        build_tcp_syn(src, dst, sport, dport, ts),
        build_tcp_synack(dst, src, dport, sport, ts + 0.001),
        build_tcp_data(src, dst, sport, dport, ts + 0.002, payload_len=0),
    ]


def _dga_name(rng: random.Random, family: int, counter: int) -> str:
    """Generate a DGA-like domain name from one of three families."""
    if family == 0:
        # Random alphanumeric
        length = rng.randint(10, 20)
        name = "".join(rng.choices(string.ascii_lowercase + string.digits, k=length))
    elif family == 1:
        # Hash-of-counter hex style
        import hashlib
        name = hashlib.md5(f"seed{counter}".encode()).hexdigest()[:16]
    else:
        # Dictionary-word concatenation
        words = ["cat", "run", "big", "box", "fly", "sun", "dog", "red", "far", "log"]
        name = "".join(rng.choices(words, k=rng.randint(3, 5)))
    return f"{name}.example-malware.com"


def _benign_name(rng: random.Random) -> str:
    """Generate a realistic-looking benign domain name."""
    tlds = [".com", ".net", ".org", ".io", ".co.uk"]
    words = ["news", "mail", "shop", "blog", "api", "cdn", "static",
             "images", "assets", "www", "media", "update", "data"]
    w1 = rng.choice(words)
    w2 = rng.choice(words)
    tld = rng.choice(tlds)
    return f"{w1}-{w2}{tld}"


# ---------------------------------------------------------------------------
# BENIGN SCENARIOS
# ---------------------------------------------------------------------------

def benign_web_browsing(rng: random.Random, base_ts: float = 0.0,
                        n_clients: int = 3, duration: float = 60.0) -> Tuple[Packets, Labels]:
    """Web browsing simulation: HTTP/HTTPS flows from internal clients."""
    pkts = []
    internal = [internal_host(i) for i in range(n_clients)]
    server = external_host(0)
    for i, client in enumerate(internal):
        n_flows = rng.randint(5, 15)
        ts = base_ts + i * 2.0
        for j in range(n_flows):
            sport = rng.randint(49152, 65535)
            dport = 443 if rng.random() > 0.3 else 80
            # Handshake
            pkts.extend(_tcp_handshake(client, server, sport, dport, ts))
            # Data exchange
            n_req = rng.randint(1, 4)
            for k in range(n_req):
                ts += rng.uniform(0.05, 0.5)
                pkts.append(build_tcp_data(client, server, sport, dport, ts,
                                           payload_len=rng.randint(200, 1400)))
                ts += rng.uniform(0.01, 0.2)
                pkts.append(build_tcp_data(server, client, dport, sport, ts,
                                           payload_len=rng.randint(200, 8000)))
            # FIN
            pkts.append(build_tcp_fin(client, server, sport, dport, ts + 0.01))
            ts += rng.uniform(2.0, 8.0)
    return pkts, []  # benign → no label intervals


def benign_bulk_download(rng: random.Random, base_ts: float = 0.0) -> Tuple[Packets, Labels]:
    """Large asymmetric download that resembles exfil — hard negative."""
    pkts = []
    client = internal_host(10)
    server = external_host(1)
    sport = rng.randint(49152, 65535)
    ts = base_ts
    pkts.extend(_tcp_handshake(client, server, sport, 443, ts))
    ts += 0.1
    # Client sends small requests, server sends large responses
    for _ in range(50):
        pkts.append(build_tcp_data(client, server, sport, 443, ts,
                                   payload_len=rng.randint(100, 300)))
        ts += rng.uniform(0.01, 0.05)
        pkts.append(build_tcp_data(server, client, 443, sport, ts,
                                   payload_len=rng.randint(8000, 65000)))
        ts += rng.uniform(0.01, 0.1)
    pkts.append(build_tcp_fin(client, server, sport, 443, ts))
    return pkts, []


def benign_flash_crowd(rng: random.Random, base_ts: float = 0.0) -> Tuple[Packets, Labels]:
    """Many clients → one server simultaneously (resembles DDoS) — hard negative."""
    pkts = []
    server = external_host(2)
    n = 200
    for i in range(n):
        client = internal_host(i % 50)
        sport = rng.randint(49152, 65535)
        ts = base_ts + rng.uniform(0, 5.0)
        pkts.extend(_tcp_handshake(client, server, sport, 80, ts))
        pkts.append(build_tcp_data(client, server, sport, 80, ts + 0.05,
                                   payload_len=rng.randint(200, 600)))
        pkts.append(build_tcp_data(server, client, 80, sport, ts + 0.1,
                                   payload_len=rng.randint(500, 4000)))
    return pkts, []


def benign_periodic_poller(rng: random.Random, base_ts: float = 0.0,
                           period: float = 30.0, n_polls: int = 40) -> Tuple[Packets, Labels]:
    """Legitimate periodic health-check/NTP (resembles beacon) — hard negative."""
    pkts = []
    client = internal_host(20)
    server = external_host(3)
    for i in range(n_polls):
        ts = base_ts + i * period + rng.uniform(-0.5, 0.5)
        sport = rng.randint(49152, 65535)
        pkts.append(build_udp(client, server, sport, 123, ts, payload_len=48))  # NTP
    return pkts, []


def benign_dns_normal(rng: random.Random, base_ts: float = 0.0,
                      n_queries: int = 100) -> Tuple[Packets, Labels]:
    """Normal DNS traffic with real-looking names."""
    pkts = []
    client = internal_host(5)
    dns_srv = external_host(5)
    for i in range(n_queries):
        ts = base_ts + i * rng.uniform(0.5, 3.0)
        qname = _benign_name(rng)
        sport = rng.randint(49152, 65535)
        pkts.append(build_dns_query(client, dns_srv, sport, ts, qname))
        pkts.append(build_dns_response(dns_srv, client, sport, ts + 0.02, qname,
                                       rcode=0, answer=str(external_host(rng.randint(0, 50)))))
    return pkts, []


# ---------------------------------------------------------------------------
# THREAT SCENARIOS
# ---------------------------------------------------------------------------

def threat_ddos_syn_flood(rng: random.Random, base_ts: float = 0.0,
                          n_sources: int = 500, duration: float = 30.0,
                          rate_pps: float = 200.0) -> Tuple[Packets, Labels]:
    """SYN flood from many spoofed sources."""
    pkts = []
    victim = external_host(0)
    start = base_ts
    total = int(duration * rate_pps)
    for i in range(total):
        src = botnet_source(rng.randint(0, n_sources - 1))
        sport = rng.randint(1024, 65535)
        ts = base_ts + i / rate_pps
        pkts.append(build_tcp_syn(src, victim, sport, 80, ts))
    labels = [{"threat": "DDOS", "src_ip": None, "dst_ip": victim,
               "start_ts": start, "end_ts": start + duration,
               "note": "SYN flood"}]
    return pkts, labels


def threat_ddos_udp_flood(rng: random.Random, base_ts: float = 0.0,
                          n_sources: int = 100, duration: float = 30.0,
                          rate_pps: float = 500.0) -> Tuple[Packets, Labels]:
    """UDP flood."""
    pkts = []
    victim = external_host(1)
    start = base_ts
    total = int(duration * rate_pps)
    for i in range(total):
        src = botnet_source(rng.randint(0, n_sources - 1))
        sport = rng.randint(1024, 65535)
        ts = base_ts + i / rate_pps
        pkts.append(build_udp(src, victim, sport, rng.randint(1, 65535), ts,
                               payload_len=rng.randint(64, 1400)))
    labels = [{"threat": "DDOS", "src_ip": None, "dst_ip": victim,
               "start_ts": start, "end_ts": start + duration,
               "note": "UDP flood"}]
    return pkts, labels


def threat_ddos_icmp_flood(rng: random.Random, base_ts: float = 0.0,
                           n_sources: int = 50, duration: float = 20.0,
                           rate_pps: float = 100.0) -> Tuple[Packets, Labels]:
    """ICMP flood."""
    pkts = []
    victim = external_host(2)
    start = base_ts
    total = int(duration * rate_pps)
    for i in range(total):
        src = botnet_source(rng.randint(0, n_sources - 1))
        ts = base_ts + i / rate_pps
        pkts.append(build_icmp_echo(src, victim, ts))
    labels = [{"threat": "DDOS", "src_ip": None, "dst_ip": victim,
               "start_ts": start, "end_ts": start + duration,
               "note": "ICMP flood"}]
    return pkts, labels


def threat_c2_beacon(rng: random.Random, base_ts: float = 0.0,
                     period: float = 60.0, jitter: float = 0.10,
                     n_beacons: int = 30,
                     beacon_size: int = 128) -> Tuple[Packets, Labels]:
    """Periodic C2 beaconing with jitter."""
    pkts = []
    bot = internal_host(50)
    c2 = external_host(10)
    sport = rng.randint(49152, 65535)
    start = base_ts
    for i in range(n_beacons):
        ts = base_ts + i * period + rng.gauss(0, period * jitter)
        ts = max(base_ts, ts)
        pkts.append(build_tcp_syn(bot, c2, sport, 443, ts))
        pkts.append(build_tcp_synack(c2, bot, 443, sport, ts + 0.001))
        pkts.append(build_tcp_data(bot, c2, sport, 443, ts + 0.002, payload_len=beacon_size))
        response_size = rng.choice([64, 64, 64, 512])  # occasional large tasking
        pkts.append(build_tcp_data(c2, bot, 443, sport, ts + 0.05, payload_len=response_size))
        pkts.append(build_tcp_fin(bot, c2, sport, 443, ts + 0.06))
    end = base_ts + n_beacons * period
    labels = [{"threat": "C2_BEACONING", "src_ip": bot, "dst_ip": c2,
               "start_ts": start, "end_ts": end,
               "note": f"periodic beacon period={period}s jitter={jitter*100:.0f}%"}]
    return pkts, labels


def threat_dga_queries(rng: random.Random, base_ts: float = 0.0,
                       n_queries: int = 300, family: int = 0) -> Tuple[Packets, Labels]:
    """DGA-like DNS query burst with high NXDOMAIN share."""
    pkts = []
    bot = internal_host(60)
    dns_srv = external_host(5)
    start = base_ts
    nxdomain_share = 0.7
    for i in range(n_queries):
        ts = base_ts + i * rng.uniform(0.1, 0.5)
        qname = _dga_name(rng, family, i)
        sport = rng.randint(49152, 65535)
        pkts.append(build_dns_query(bot, dns_srv, sport, ts, qname))
        rcode = 3 if rng.random() < nxdomain_share else 0
        pkts.append(build_dns_response(dns_srv, bot, sport, ts + 0.02, qname,
                                       rcode=rcode))
    labels = [{"threat": "DNS_DGA_TUNNEL", "src_ip": bot, "dst_ip": None,
               "start_ts": start, "end_ts": ts,
               "note": f"DGA queries family={family}"}]
    return pkts, labels


def threat_dns_tunnel(rng: random.Random, base_ts: float = 0.0,
                      n_queries: int = 200) -> Tuple[Packets, Labels]:
    """DNS tunnelling: long high-entropy subdomain labels."""
    import base64
    pkts = []
    exfil_host = internal_host(70)
    dns_srv = external_host(5)
    tunnel_domain = "tunnel.attacker-domain.example"
    start = base_ts
    for i in range(n_queries):
        ts = base_ts + i * rng.uniform(0.05, 0.3)
        # Base64-like subdomain carrying data
        data = bytes(rng.randint(0, 255) for _ in range(rng.randint(20, 40)))
        subdomain = base64.b32encode(data).decode("ascii").lower().rstrip("=")[:40]
        qname = f"{subdomain}.{tunnel_domain}"
        sport = rng.randint(49152, 65535)
        pkts.append(build_dns_query(exfil_host, dns_srv, sport, ts, qname))
        # Response carries data back in TXT-like answer
        pkts.append(build_dns_response(dns_srv, exfil_host, sport, ts + 0.02, qname))
    labels = [{"threat": "DNS_DGA_TUNNEL", "src_ip": exfil_host, "dst_ip": None,
               "start_ts": start, "end_ts": ts,
               "note": "DNS tunnelling long-subdomain"}]
    return pkts, labels


def threat_recon_horizontal(rng: random.Random, base_ts: float = 0.0,
                             n_hosts: int = 100, port: int = 22) -> Tuple[Packets, Labels]:
    """Horizontal sweep: one scanner, one port, many hosts."""
    pkts = []
    scanner = internal_host(80)
    start = base_ts
    for i in range(n_hosts):
        target = internal_host(100 + i)
        sport = rng.randint(49152, 65535)
        ts = base_ts + i * rng.uniform(0.01, 0.1)
        pkts.append(build_tcp_syn(scanner, target, sport, port, ts))
        # Half-open: mostly no SYN-ACK back (unidirectional)
        if rng.random() < 0.1:
            pkts.append(build_tcp_rst(target, scanner, port, sport, ts + 0.01))
    labels = [{"threat": "RECON_PORT_SCAN", "src_ip": scanner, "dst_ip": None,
               "start_ts": start, "end_ts": ts,
               "note": "horizontal sweep"}]
    return pkts, labels


def threat_recon_vertical(rng: random.Random, base_ts: float = 0.0,
                           target_ip_idx: int = 200,
                           n_ports: int = 137) -> Tuple[Packets, Labels]:
    """Vertical scan: one scanner, one host, many ports."""
    pkts = []
    scanner = internal_host(90)
    target = internal_host(target_ip_idx)
    start = base_ts
    ports = rng.sample(range(1, 65535), n_ports)
    for i, port in enumerate(ports):
        sport = rng.randint(49152, 65535)
        ts = base_ts + i * rng.uniform(0.005, 0.05)
        pkts.append(build_tcp_syn(scanner, target, sport, port, ts))
        if port in (22, 80, 443) and rng.random() < 0.5:
            pkts.append(build_tcp_synack(target, scanner, port, sport, ts + 0.002))
    labels = [{"threat": "RECON_PORT_SCAN", "src_ip": scanner, "dst_ip": target,
               "start_ts": start, "end_ts": ts,
               "note": f"vertical scan {n_ports} ports"}]
    return pkts, labels


def threat_exfiltration(rng: random.Random, base_ts: float = 0.0,
                         total_mb: float = 50.0) -> Tuple[Packets, Labels]:
    """Sustained large outbound data transfer to a novel external host."""
    pkts = []
    src = internal_host(110)
    dst = external_host(20)
    sport = rng.randint(49152, 65535)
    start = base_ts
    ts = base_ts
    pkts.extend(_tcp_handshake(src, dst, sport, 443, ts))
    ts += 0.1
    total_bytes = int(total_mb * 1_000_000)
    chunk = 8000  # ~8 KB per packet
    n_pkts = total_bytes // chunk
    for i in range(n_pkts):
        pkts.append(build_tcp_data(src, dst, sport, 443, ts, payload_len=chunk))
        ts += rng.uniform(0.001, 0.005)
        if rng.random() < 0.02:
            pkts.append(build_tcp_data(dst, src, 443, sport, ts, payload_len=64))
    pkts.append(build_tcp_fin(src, dst, sport, 443, ts))
    labels = [{"threat": "DATA_EXFILTRATION", "src_ip": src, "dst_ip": dst,
               "start_ts": start, "end_ts": ts,
               "note": f"exfil {total_mb:.0f} MB outbound"}]
    return pkts, labels


def threat_encrypted_malware_tls(rng: random.Random, base_ts: float = 0.0,
                                  n_sessions: int = 10) -> Tuple[Packets, Labels]:
    """
    Simulated TLS malware sessions via metadata-only patterns.
    Payload bytes are random (no real TLS crypto).
    Pattern: uniform small records + long idle + bursts.
    NOTE: fingerprint differences here are synthetic assumptions, not real families.
    """
    pkts = []
    bot = internal_host(120)
    c2 = external_host(15)
    start = base_ts
    for i in range(n_sessions):
        sport = rng.randint(49152, 65535)
        ts = base_ts + i * rng.uniform(10, 30)
        pkts.extend(_tcp_handshake(bot, c2, sport, 443, ts))
        ts += 0.5
        # Uniform small records (atypical for browsing)
        for _ in range(rng.randint(8, 15)):
            size = rng.randint(60, 80)  # very uniform
            pkts.append(build_tcp_data(bot, c2, sport, 443, ts, payload_len=size))
            ts += rng.uniform(0.01, 0.03)
        # Long idle
        ts += rng.uniform(5, 15)
        # Burst
        burst_size = rng.randint(20000, 60000)
        pkts.append(build_tcp_data(bot, c2, sport, 443, ts, payload_len=burst_size))
        ts += 0.1
        pkts.append(build_tcp_fin(bot, c2, sport, 443, ts))
    labels = [{"threat": "ENCRYPTED_MALWARE", "src_ip": bot, "dst_ip": c2,
               "start_ts": start, "end_ts": ts,
               "note": "synthetic TLS metadata pattern (not real malware fingerprint)"}]
    return pkts, labels

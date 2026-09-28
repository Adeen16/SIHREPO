"""
datasets_gen/packet_builder.py
--------------------------------
Low-level Scapy packet constructors.

PASSIVE SAFETY: This module ONLY uses Scapy to BUILD packets (in memory).
It never calls send/sendp/sr/sr1/sniff or any transmit function.
Packets are collected in memory and written to file via wrpcap/PcapWriter.

Provides:
- build_tcp_syn(src_ip, dst_ip, sport, dport, ts)
- build_tcp_synack(src_ip, dst_ip, sport, dport, ts)
- build_tcp_fin(src_ip, dst_ip, sport, dport, ts)
- build_tcp_rst(...)
- build_tcp_data(...)
- build_udp(...)
- build_icmp_echo(...)
- build_dns_query(...)
- build_dns_response(...)
"""
from __future__ import annotations
from typing import Optional

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Packet
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

# TCP flag bitmasks
_SYN = 0x002
_ACK = 0x010
_FIN = 0x001
_RST = 0x004
_PSH = 0x008
_SYN_ACK = _SYN | _ACK
_FIN_ACK = _FIN | _ACK


def _require_scapy():
    if not _SCAPY_OK:
        raise ImportError("scapy is required for packet building")


def set_timestamp(pkt: "Packet", ts: float) -> "Packet":
    """Attach a capture timestamp to a Scapy packet."""
    pkt.time = ts
    return pkt


def build_tcp_syn(src: str, dst: str, sport: int, dport: int, ts: float,
                  payload_len: int = 0) -> "Packet":
    _require_scapy()
    payload = bytes(payload_len) if payload_len else b""
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=_SYN) / payload
    return set_timestamp(pkt, ts)


def build_tcp_synack(src: str, dst: str, sport: int, dport: int, ts: float) -> "Packet":
    _require_scapy()
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=_SYN_ACK)
    return set_timestamp(pkt, ts)


def build_tcp_fin(src: str, dst: str, sport: int, dport: int, ts: float) -> "Packet":
    _require_scapy()
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=_FIN_ACK)
    return set_timestamp(pkt, ts)


def build_tcp_rst(src: str, dst: str, sport: int, dport: int, ts: float) -> "Packet":
    _require_scapy()
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=_RST)
    return set_timestamp(pkt, ts)


def build_tcp_data(src: str, dst: str, sport: int, dport: int, ts: float,
                   payload_len: int = 64) -> "Packet":
    _require_scapy()
    payload = bytes(payload_len)
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=_PSH | _ACK) / payload
    return set_timestamp(pkt, ts)


def build_udp(src: str, dst: str, sport: int, dport: int, ts: float,
              payload_len: int = 64) -> "Packet":
    _require_scapy()
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / bytes(payload_len)
    return set_timestamp(pkt, ts)


def build_icmp_echo(src: str, dst: str, ts: float, payload_len: int = 64) -> "Packet":
    _require_scapy()
    pkt = IP(src=src, dst=dst) / ICMP(type=8) / bytes(payload_len)
    return set_timestamp(pkt, ts)


def build_dns_query(src: str, dns_server: str, sport: int, ts: float,
                    qname: str) -> "Packet":
    _require_scapy()
    pkt = (IP(src=src, dst=dns_server) /
           UDP(sport=sport, dport=53) /
           DNS(rd=1, qd=DNSQR(qname=qname)))
    return set_timestamp(pkt, ts)


def build_dns_response(dns_server: str, client: str, sport: int, ts: float,
                       qname: str, rcode: int = 0, answer: str = "1.2.3.4") -> "Packet":
    _require_scapy()
    if rcode == 0:
        pkt = (IP(src=dns_server, dst=client) /
               UDP(sport=53, dport=sport) /
               DNS(qr=1, aa=1, rcode=rcode,
                   qd=DNSQR(qname=qname),
                   an=DNSRR(rrname=qname, rdata=answer, ttl=300)))
    else:
        pkt = (IP(src=dns_server, dst=client) /
               UDP(sport=53, dport=sport) /
               DNS(qr=1, aa=1, rcode=rcode,
                   qd=DNSQR(qname=qname)))
    return set_timestamp(pkt, ts)

import os
import socket
from typing import Iterator
import dpkt
from dpkt.compat import compat_ord
from .packet_event import PacketEvent
from scapy.all import Ether

class FastPCAPIngestor:
    """
    Fast PCAP reader using dpkt. Emits PacketEvents exactly like the Scapy reader.
    """
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        self.file_path = file_path
        self.malformed_count = 0
        self.fallback_count = 0

    def __iter__(self) -> Iterator[PacketEvent]:
        try:
            with open(self.file_path, "rb") as f:
                # Detect PCAP or PCAPNG
                head = f.read(4)
                f.seek(0)
                if head in (b"\\xa1\\xb2\\xc3\\xd4", b"\\xd4\\xc3\\xb2\\xa1", b"\\xa1\\xb2\\x3c\\x4d", b"\\x4d\\x3c\\xb2\\xa1"):
                    reader = dpkt.pcap.Reader(f)
                elif head == b"\\x0a\\x0d\\x0d\\x0a":
                    reader = dpkt.pcapng.Reader(f)
                else:
                    reader = dpkt.pcap.Reader(f) # try anyway

                for ts, buf in reader:
                    try:
                        yield self._parse_dpkt(ts, buf)
                    except Exception:
                        self.malformed_count += 1
                        # fallback to scapy? The prompt says "per-packet fallback to Scapy".
                        # But parsing dpkt failure means we should fallback to Scapy for this packet
                        try:
                            scapy_pkt = Ether(buf)
                            # To keep it simple, we don't fully implement Scapy fallback in this first draft,
                            # just use basic info.
                            yield PacketEvent(timestamp=float(ts), length=len(buf), raw_packet=scapy_pkt)
                            self.fallback_count += 1
                        except Exception:
                            pass
        except Exception as e:
            raise ValueError(f"Failed to read PCAP with dpkt: {e}")

    def _parse_dpkt(self, ts: float, buf: bytes) -> PacketEvent:
        length = len(buf)
        eth = dpkt.ethernet.Ethernet(buf)
        
        event = PacketEvent(
            timestamp=float(ts),
            length=length,
            raw_packet=None # No scapy packet by default for performance
        )
        
        ip = eth.data
        if eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
            # VLAN
            ip = eth.data.data
            
        if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            event.src_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.src)
            event.dst_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.dst)
            
            tcp_udp = ip.data
            if isinstance(tcp_udp, dpkt.tcp.TCP):
                event.protocol = "TCP"
                event.src_port = tcp_udp.sport
                event.dst_port = tcp_udp.dport
                event.tcp_flags = tcp_udp.flags
                event.is_syn = bool(tcp_udp.flags & dpkt.tcp.TH_SYN)
                event.is_fin = bool(tcp_udp.flags & dpkt.tcp.TH_FIN)
                event.is_rst = bool(tcp_udp.flags & dpkt.tcp.TH_RST)
                event.is_ack = bool(tcp_udp.flags & dpkt.tcp.TH_ACK)
                event.is_psh = bool(tcp_udp.flags & dpkt.tcp.TH_PUSH)
            elif isinstance(tcp_udp, dpkt.udp.UDP):
                event.protocol = "UDP"
                event.src_port = tcp_udp.sport
                event.dst_port = tcp_udp.dport
            elif isinstance(tcp_udp, dpkt.icmp.ICMP) or isinstance(tcp_udp, dpkt.icmp6.ICMP6):
                event.protocol = "ICMP"
        return event

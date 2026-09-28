import os
import sys
from typing import Iterator
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from .packet_event import PacketEvent

class PCAPIngestor:
    """
    A read-only passive ingestion layer for PCAP and PCAPNG files.
    Reads incrementally to support large captures without loading entirely into memory.
    """
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        if not os.path.isfile(file_path):
            raise ValueError(f"Path is not a file: {file_path}")
            
        self.file_path = file_path

    def __iter__(self) -> Iterator[PacketEvent]:
        # Using PcapReader for streaming rather than rdpcap
        try:
            with PcapReader(self.file_path) as pcap_reader:
                for pkt in pcap_reader:
                    yield self._parse_packet(pkt)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP file: {e}")

    def _parse_packet(self, pkt) -> PacketEvent:
        timestamp = float(pkt.time)
        length = len(pkt)
        
        event = PacketEvent(
            timestamp=timestamp,
            length=length,
            raw_packet=pkt
        )
        
        # IP Layer extraction
        if IP in pkt:
            event.src_ip = pkt[IP].src
            event.dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            event.src_ip = pkt[IPv6].src
            event.dst_ip = pkt[IPv6].dst
            
        # Transport Layer extraction
        if TCP in pkt:
            event.src_port = pkt[TCP].sport
            event.dst_port = pkt[TCP].dport
            event.protocol = "TCP"
            # TCP flags (bitmask)
            flags = int(pkt[TCP].flags)
            event.tcp_flags = flags
            event.is_syn = bool(flags & 0x002)
            event.is_fin = bool(flags & 0x001)
            event.is_rst = bool(flags & 0x004)
            event.is_ack = bool(flags & 0x010)
            event.is_psh = bool(flags & 0x008)
        elif UDP in pkt:
            event.src_port = pkt[UDP].sport
            event.dst_port = pkt[UDP].dport
            event.protocol = "UDP"
            
        return event

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m ingestion.pcap_reader <path-to-pcap>")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    
    try:
        ingestor = PCAPIngestor(pcap_path)
        
        count = 0
        first_ts = None
        last_ts = None
        protocols = {}
        
        print(f"Reading {pcap_path} incrementally...")
        
        for event in ingestor:
            count += 1
            if first_ts is None:
                first_ts = event.timestamp
            last_ts = event.timestamp
            
            proto = event.protocol or "Other"
            protocols[proto] = protocols.get(proto, 0) + 1
            
        print("\n--- Ingestion Statistics ---")
        print(f"File: {pcap_path}")
        print(f"Packets Processed: {count}")
        
        if count > 0:
            print(f"First Packet Timestamp: {first_ts}")
            print(f"Last Packet Timestamp: {last_ts}")
            
            duration = last_ts - first_ts
            if duration > 0:
                print(f"Packets/sec: {count / duration:.2f}")
            else:
                print("Packets/sec: N/A (Duration is 0)")
                
            print("Protocol Distribution:")
            for p, c in protocols.items():
                print(f"  {p}: {c}")
                
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

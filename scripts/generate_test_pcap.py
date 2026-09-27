import sys
import os
from scapy.all import IP, TCP, UDP, Ether, wrpcap

def generate_test_pcap(path):
    pkts = [
        Ether()/IP(src="192.168.1.100", dst="10.0.0.50")/TCP(sport=54321, dport=443),
        Ether()/IP(src="10.0.0.50", dst="192.168.1.100")/TCP(sport=443, dport=54321),
        Ether()/IP(src="192.168.1.101", dst="8.8.8.8")/UDP(sport=53, dport=53),
        Ether()/IP(src="8.8.8.8", dst="192.168.1.101")/UDP(sport=53, dport=53),
        Ether()/IP(src="10.1.1.1", dst="10.2.2.2")/TCP(sport=22, dport=22)
    ]

    # Assign incrementing timestamps
    base_time = 1700000000.0
    for i, pkt in enumerate(pkts):
        pkt.time = base_time + (i * 0.1)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrpcap(path, pkts)
    print(f"Generated {path} with {len(pkts)} packets.")

if __name__ == "__main__":
    generate_test_pcap(sys.argv[1])

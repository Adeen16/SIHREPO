import os
import time
from collections import defaultdict
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, IP, TCP, UDP, DNSQR

PCAPS = {
    "DDoS": "NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap",
    "C2_BEACONING": "NTRO-Datasets/PCAPS/03_c2_beaconing/botnet-capture-20110810-neris.pcap",
    "DNS_DGA_TUNNEL": "NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap",
    "ENCRYPTED_MALWARE": "NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap"
}

def analyze_pcap(name, rel_path, max_packets=500000):
    pcap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', rel_path))
    if not os.path.exists(pcap_path):
        print(f"Skipping {name}: not found at {pcap_path}")
        return

    print(f"\n[{name}] Analyzing {rel_path}...")

    bin_size = 10.0 # 10 second bins
    bins = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "unique_src_ips": set(),
        "unique_dst_ips": set(),
        "tcp": 0,
        "udp": 0,
        "dns": 0,
        "start_packet_idx": -1,
        "end_packet_idx": -1
    })

    start_time = time.time()
    packet_count = 0
    first_ts = None

    try:
        with PcapReader(pcap_path) as reader:
            for packet in reader:
                packet_count += 1
                if packet_count > max_packets:
                    break

                if not packet.haslayer(IP):
                    continue

                ts = float(packet.time)
                if first_ts is None:
                    first_ts = ts

                bin_idx = int((ts - first_ts) / bin_size)
                b = bins[bin_idx]

                if b["start_packet_idx"] == -1:
                    b["start_packet_idx"] = packet_count
                b["end_packet_idx"] = packet_count
                b["packets"] += 1
                b["bytes"] += len(packet)
                b["unique_src_ips"].add(packet[IP].src)
                b["unique_dst_ips"].add(packet[IP].dst)

                if packet.haslayer(TCP):
                    b["tcp"] += 1
                elif packet.haslayer(UDP):
                    b["udp"] += 1

                if packet.haslayer(DNSQR):
                    b["dns"] += 1

                if packet_count % 50000 == 0:
                    print(f"  ... {packet_count} packets read")
    except Exception as e:
        print(f"Error reading {name}: {e}")

    elapsed = time.time() - start_time
    print(f"  -> Finished parsing {packet_count} packets in {elapsed:.2f}s")

    # Analyze bins to find the "peak" of activity for this threat type
    valid_bins = [k for k in sorted(bins.keys()) if bins[k]["packets"] > 0]

    if not valid_bins:
        print("  -> No IP packets found.")
        return

    print(f"  -> Total Bins: {len(valid_bins)}, Time range: ~{valid_bins[-1]*bin_size} seconds")

    # Sort bins depending on the threat type to find the candidate region
    if name == "DDoS":
        # Highest packet rate
        top_bins = sorted(valid_bins, key=lambda k: bins[k]["packets"], reverse=True)[:3]
        print("  -> Top DDoS Candidate Regions (by packet volume):")
    elif name == "DNS_DGA_TUNNEL":
        # Highest DNS query rate
        top_bins = sorted(valid_bins, key=lambda k: bins[k]["dns"], reverse=True)[:3]
        print("  -> Top DNS Tunnel Candidate Regions (by DNS queries):")
    elif name == "C2_BEACONING":
        # Sustained low-volume TCP/UDP with regular intervals. Look for highest TCP.
        top_bins = sorted(valid_bins, key=lambda k: bins[k]["tcp"], reverse=True)[:3]
        print("  -> Top C2 Candidate Regions (by TCP volume):")
    elif name == "ENCRYPTED_MALWARE":
        # Similar to C2, look for SSL/TLS (TCP 443). We just sort by TCP volume for now.
        top_bins = sorted(valid_bins, key=lambda k: bins[k]["tcp"], reverse=True)[:3]
        print("  -> Top Encrypted Malware Candidate Regions (by TCP volume):")

    for k in top_bins:
        b = bins[k]
        print(f"     Bin {k*10}s - {(k+1)*10}s | Packets: {b['packets']} ({b['start_packet_idx']} to {b['end_packet_idx']}) | DNS: {b['dns']} | TCP: {b['tcp']} | UDP: {b['udp']} | Dst IPs: {len(b['unique_dst_ips'])}")

if __name__ == "__main__":
    for name, path in PCAPS.items():
        analyze_pcap(name, path)

import os
import sys
import logging
from ingestion.pcap_reader import PCAPIngestor
from processing.window import SlidingWindowManager

def get_ddos_rate():
    pcap_path = os.path.abspath("NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap")
    ingestor = PCAPIngestor(pcap_path)
    window_manager = SlidingWindowManager(window_seconds=1.0, slide_seconds=1.0)

    count = 0
    max_pps = 0
    max_flows = 0

    for packet in ingestor:
        count += 1
        snapshots = window_manager.add_packet(packet)
        for s in snapshots:
            if s.total_packets > max_pps:
                max_pps = s.total_packets
            if s.flow_count > max_flows:
                max_flows = s.flow_count

        if count > 50000:
            break

    print(f"Max PPS: {max_pps}")
    print(f"Max Flows per sec: {max_flows}")

if __name__ == "__main__":
    get_ddos_rate()

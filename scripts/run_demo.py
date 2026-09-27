import os
import sys
import time
import logging
from typing import List

# Setup path so it can import from root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.pcap_reader import PCAPIngestor
from ingestion.packet_event import PacketEvent
from detection.orchestrator import DetectionOrchestrator

logging.basicConfig(level=logging.WARNING)

PCAPS = {
    "BENIGN": "NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap",
    "DDoS": "NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap",
    "C2_BEACONING": "NTRO-Datasets/PCAPS/03_c2_beaconing/botnet-capture-20110810-neris.pcap",
    "DNS_DGA_TUNNEL": "NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap",
    "ENCRYPTED_MALWARE": "NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap",
    "RECON_PORT_SCAN": "NTRO-Datasets/PCAPS/06_reconnaissance/botnet-capture-20110812-rbot.pcap"
}

def generate_synthetic_exfiltration_packets() -> List[PacketEvent]:
    """
    Generates a deterministic sequence of PacketEvents to simulate data exfiltration.
    A single machine connects to an external IP and sends 2MB of data in a short burst,
    while receiving very little data back.
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.100"
    dst_ip = "203.0.113.50"

    # Send 1500 packets of 1400 bytes outbound
    for i in range(1500):
        packets.append(PacketEvent(
            timestamp=base_time + (i * 0.01),
            length=1400,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=55555,
            dst_port=443,
            protocol='TCP'
        ))
        # Every 10 packets, send 1 small ACK inbound
        if i % 10 == 0:
            packets.append(PacketEvent(
                timestamp=base_time + (i * 0.01) + 0.005,
                length=60,
                src_ip=dst_ip,
                dst_ip=src_ip,
                src_port=443,
                dst_port=55555,
                protocol='TCP'
            ))

    return packets

def run_demo(max_packets=50000):
    print("==================================================")
    print("   SIH 145 PS 145 THREAT DETECTION DEMONSTRATION  ")
    print("==================================================")

    model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'baseline'))

    for category, pcap_rel_path in PCAPS.items():
        pcap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', pcap_rel_path))
        print(f"\nEvaluating Category: {category}")
        print(f"File: {pcap_rel_path}")

        if not os.path.exists(pcap_path):
            print(f"  -> File not found. Skipping.")
            continue

        try:
            orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=10.0, slide_seconds=2.0)
        except Exception as e:
            print(f"  -> Failed to initialize orchestrator: {e}")
            continue

        ingestor = PCAPIngestor(pcap_path)
        packet_count = 0
        detections = []

        print(f"  -> Processing up to {max_packets} packets...")
        try:
            for packet in ingestor:
                packet_count += 1
                if packet_count % 10000 == 0:
                    print(f"    ... processed {packet_count} packets")
                try:
                    results = orchestrator.process_packet(packet)
                except ValueError:
                    continue

                if results:
                    for res in results:
                        if res.status == "DETECTED":
                            res.validation_source = "REAL_PCAP"
                            detections.append(res)

                if packet_count >= max_packets:
                    break
        except Exception as e:
            print(f"  -> Error processing PCAP: {e}")

        print(f"  -> Processed {packet_count} packets.")
        summarize_detections(detections)

    # Synthetic Fixture for Data Exfiltration
    print(f"\nEvaluating Category: DATA_EXFILTRATION (SYNTHETIC/CONTROLLED VALIDATION)")
    print(f"File: Memory Fixture (Synthetic Exfiltration Stream)")
    try:
        orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=10.0, slide_seconds=2.0)
        packets = generate_synthetic_exfiltration_packets()
        detections = []

        for packet in packets:
            try:
                results = orchestrator.process_packet(packet)
                if results:
                    for res in results:
                        if res.status == "DETECTED":
                            # We explicitly tag it as SYNTHETIC
                            res.validation_source = "CONTROLLED/SYNTHETIC_FIXTURE"
                            detections.append(res)
            except ValueError:
                continue

        print(f"  -> Processed {len(packets)} synthetic packets.")
        summarize_detections(detections)
    except Exception as e:
        print(f"  -> Error processing synthetic fixture: {e}")

def summarize_detections(detections):
    print(f"  -> Total Threat Detections Triggered: {len(detections)}")

    threats_found = {}
    for d in detections:
        threats_found[d.threat_type] = threats_found.get(d.threat_type, 0) + 1

    for t_type, count in threats_found.items():
        print(f"     [!] {t_type}: {count} alerts")

    if detections:
        sample = detections[0]
        print(f"     [Evidence Sample - {sample.threat_type}]:")
        print(f"       Validation Source: {sample.validation_source}")
        print(f"       Flow ID: {sample.flow_id}")
        print(f"       Severity: {sample.severity}")
        print(f"       Confidence: {sample.confidence or sample.score}")
        print(f"       Details: {sample.evidence}")

if __name__ == "__main__":
    run_demo()

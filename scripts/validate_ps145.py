import os
import sys
import json
import time
import logging
from typing import Dict, Any, List

# Setup path so it can import from root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.pcap_reader import PCAPIngestor
from detection.orchestrator import DetectionOrchestrator
from api.schemas import DetectionResponseItem

logging.basicConfig(level=logging.WARNING)

PCAPS = {
    "BENIGN": "NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap",
    "DDoS": "NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap",
    "C2_BEACONING": "NTRO-Datasets/PCAPS/03_c2_beaconing/botnet-capture-20110810-neris.pcap",
    "DNS_DGA_TUNNEL": "NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap",
    "ENCRYPTED_MALWARE": "NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap",
    "RECON_PORT_SCAN": "NTRO-Datasets/PCAPS/06_reconnaissance/botnet-capture-20110812-rbot.pcap"
}

def run_validation(category: str = None, packet_limit: int = None, start_packet: int = 0):
    print("==================================================")
    print("   SIH 145 PS 145 END-TO-END VALIDATION HARNESS   ")
    print("==================================================")

    model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'baseline'))

    validation_results = {"datasets": []}

    targets = {category: PCAPS[category]} if category and category in PCAPS else PCAPS

    for expected_category, pcap_rel_path in targets.items():
        pcap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', pcap_rel_path))

        result_record = {
            "file": pcap_rel_path,
            "expected_category": expected_category,
            "start_packet": start_packet,
            "packet_limit": packet_limit,
            "packets": 0,
            "flows": 0,
            "windows": 0,
            "detections": [],
            "status": "NOT_FOUND",
            "elapsed_seconds": 0.0,
            "packets_per_sec": 0.0
        }

        print(f"\n[VALIDATING] {expected_category} : {pcap_rel_path}")
        if packet_limit:
            print(f"  -> Bounds: packets [{start_packet} to {start_packet + packet_limit - 1}]")

        if not os.path.exists(pcap_path):
            print("  -> File not found. Skipping.")
            validation_results["datasets"].append(result_record)
            continue

        try:
            orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=10.0, slide_seconds=2.0)
        except Exception as e:
            print(f"  -> Failed to initialize orchestrator: {e}")
            result_record["status"] = "INIT_ERROR"
            validation_results["datasets"].append(result_record)
            continue

        ingestor = PCAPIngestor(pcap_path)

        start_time = time.time()
        packet_count = 0
        detections = []

        try:
            for packet in ingestor:
                if packet_count < start_packet:
                    packet_count += 1
                    continue

                packet_count += 1
                if (packet_count - start_packet) % 1000 == 0:
                    print(f"    ... processed {packet_count - start_packet} packets")

                try:
                    results = orchestrator.process_packet(packet)
                except ValueError as ve:
                    # Ignore out-of-order packet timestamps from libpcap artifacts
                    continue

                if results:
                    result_record["windows"] += 1
                    for res in results:
                        if res.status == "DETECTED":
                            detections.append(res)

                if packet_limit and (packet_count - start_packet) >= packet_limit:
                    break
        except Exception as e:
            print(f"  -> Error processing PCAP: {e}")

        end_time = time.time()
        elapsed = end_time - start_time
        processed = packet_count - start_packet

        result_record["packets"] = processed
        result_record["elapsed_seconds"] = round(elapsed, 2)
        result_record["packets_per_sec"] = round(processed / elapsed, 2) if elapsed > 0 else 0

        print(f"  -> Packets: {processed} in {elapsed:.2f}s ({result_record['packets_per_sec']} p/s)")
        print(f"  -> Detections: {len(detections)}")

        # Store uniquely identifying detections by flow and category to avoid window overlap spam
        unique_threats = {}
        for d in detections:
            key = f"{d.flow_id}_{d.threat_type}"
            if key not in unique_threats:
                unique_threats[key] = {
                    "threat_type": d.threat_type,
                    "count": 0,
                    "evidence": d.evidence,
                    "flow_id": d.flow_id,
                    "severity": d.severity,
                    "confidence": d.confidence or d.score
                }
            unique_threats[key]["count"] += 1

        result_record["detections"] = list(unique_threats.values())
        result_record["status"] = "DETECTED" if len(unique_threats) > 0 else "BENIGN_IN_SAMPLE"

        if len(unique_threats) > 0:
            for alert in result_record["detections"]:
                print(f"     [!] {alert['threat_type']}: {alert['count']} overlapping window alerts for flow {alert['flow_id']}")

        validation_results["datasets"].append(result_record)

    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'docs', 'phase_12e_validation.json'))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'w') as f:
        json.dump(validation_results, f, indent=4)

    print(f"\nValidation complete. JSON saved to {out_file}")

if __name__ == "__main__":
    category = sys.argv[1] if len(sys.argv) > 1 else None
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    start = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    run_validation(category, limit, start)

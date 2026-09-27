import os
import sys
import logging
from typing import List

# Setup path so it can import from root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.pcap_reader import PCAPIngestor
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

def run_demo(max_packets=5000):
    print("==================================================")
    print("   SIH 145 PS 145 THREAT DETECTION DEMONSTRATION  ")
    print("==================================================")
    print(f"Initializing Orchestrator...")
    
    # Needs absolute path to models
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
                if packet_count % 100 == 0:
                    print(f"    ... processed {packet_count} packets")
                try:
                    results = orchestrator.process_packet(packet)
                except ValueError as ve:
                    # Ignore out-of-order packets
                    continue
                    
                if results:
                    # Collect valid detections (ignore BENIGN to avoid spamming demo)
                    for res in results:
                        if res.status == "DETECTED":
                            detections.append(res)
                            
                if packet_count >= max_packets:
                    break
        except Exception as e:
            print(f"  -> Error processing PCAP: {e}")
            
        print(f"  -> Processed {packet_count} packets.")
        print(f"  -> Total Threat Detections Triggered: {len(detections)}")
        
        # Summarize unique threats
        threats_found = {}
        for d in detections:
            threats_found[d.threat_type] = threats_found.get(d.threat_type, 0) + 1
            
        for t_type, count in threats_found.items():
            print(f"     [!] {t_type}: {count} alerts")
            
        # Show one evidence example if available
        if detections:
            sample = detections[0]
            print(f"     [Evidence Sample - {sample.threat_type}]:")
            print(f"       Flow ID: {sample.flow_id}")
            print(f"       Severity: {sample.severity}")
            print(f"       Confidence/Score: {sample.confidence or sample.score}")
            print(f"       Details: {sample.evidence}")

if __name__ == "__main__":
    run_demo()

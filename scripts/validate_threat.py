import os
import sys
import logging
from scapy.all import PcapReader
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ingestion.pcap_reader import PCAPIngestor
from processing.flow import FlowProcessor
from processing.window import SlidingWindowManager
from detection.orchestrator import DetectionOrchestrator

def main():
    if len(sys.argv) < 4:
        print("Usage: python validate_threat.py <pcap_rel_path> <start_packet> <packet_limit>")
        sys.exit(1)
        
    pcap_rel_path = sys.argv[1]
    start_packet = int(sys.argv[2])
    packet_limit = int(sys.argv[3])
    
    pcap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', pcap_rel_path))
    model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'native_ddos'))
    
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=10.0, slide_seconds=2.0)
    ingestor = PCAPIngestor(pcap_path)
    
    print(f"Validating {pcap_rel_path} from packet {start_packet} to {start_packet + packet_limit}")
    
    packet_count = 0
    detections = []
    
    start_time = time.time()
    
    for packet in ingestor:
        if packet_count < start_packet:
            packet_count += 1
            continue
            
        packet_count += 1
        if (packet_count - start_packet) % 10000 == 0:
            print(f"Processed {packet_count - start_packet} packets")
            
        try:
            results = orchestrator.process_packet(packet)
            if results:
                for r in results:
                    if r.status == "DETECTED":
                        detections.append(r)
        except ValueError:
            pass
            
        if (packet_count - start_packet) >= packet_limit:
            break
            
    end_time = time.time()
    
    print(f"\nCompleted in {end_time - start_time:.2f}s")
    print(f"Total Detections: {len(detections)}")
    
    unique_alerts = {}
    for d in detections:
        key = f"{d.threat_type}_{d.flow_id}"
        if key not in unique_alerts:
            unique_alerts[key] = {"count": 1, "evidence": d.evidence}
        else:
            unique_alerts[key]["count"] += 1
            
    for k, v in unique_alerts.items():
        print(f"[{k}] Count: {v['count']} Evidence: {v['evidence']}")

if __name__ == "__main__":
    main()

import os
import sys
import csv
import time
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.pcap_reader import PCAPIngestor
from processing.flow import FlowProcessor
from processing.window import SlidingWindowManager
from processing.features import FeatureExtractor
from detection.bridge import Phase6toPhase8Bridge

def extract_features_from_pcap(pcap_path: str, label: int, start_packet: int = 0, packet_limit: int = None, output_rows: List = None):
    print(f"Extracting features from {pcap_path} (Label: {label})")
    
    if output_rows is None:
        output_rows = []
        
    pcap_abs = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', pcap_path))
    ingestor = PCAPIngestor(pcap_abs)
    flow_processor = FlowProcessor()
    window_manager = SlidingWindowManager(window_seconds=10.0, slide_seconds=2.0)
    extractor = FeatureExtractor()
    bridge = Phase6toPhase8Bridge()
    
    packet_count = 0
    start_time = time.time()
    
    try:
        for packet in ingestor:
            if packet_count < start_packet:
                packet_count += 1
                continue
                
            packet_count += 1
            if (packet_count - start_packet) % 50000 == 0:
                print(f"  ... processed {packet_count - start_packet} packets")
                
            try:
                completed_windows = window_manager.add_packet(packet)
            except ValueError:
                continue
                
            for window in completed_windows:
                window_features = extractor.extract_features(window)
                for flow_id, state in window.flows.items():
                        # Minimum packet check to avoid pure noise flows
                        if state.packet_count < 3:
                            continue
                            
                        p6_features = window_features.get(flow_id)
                        if p6_features:
                            try:
                                # Use the bridge to get exact same feature order and calculation
                                vector = bridge.convert(p6_features)
                                # Vector is a 1D numpy array, convert to list and append label
                                row = vector.tolist() + [label]
                                output_rows.append(row)
                            except Exception as e:
                                pass
                                

            if packet_limit and (packet_count - start_packet) >= packet_limit:
                break
    except Exception as e:
        print(f"Error reading pcap: {e}")
            
    print(f"  -> Extracted {len(output_rows)} feature rows.")
    return output_rows

if __name__ == "__main__":
    benign_pcap = "NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap"
    ddos_pcap = "NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap"
    
    output_rows = []
    
    # Extract Benign (Label 0). Use a representative 100k packets
    extract_features_from_pcap(benign_pcap, 0, start_packet=0, packet_limit=100000, output_rows=output_rows)
    
    # Wait for find_attack_regions to finish to know exactly where the DDoS is, but for now we'll extract 100k packets starting at a high index
    start_ddos = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    limit_ddos = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
    
    last_len = len(output_rows)
    extract_features_from_pcap(ddos_pcap, 1, start_packet=start_ddos, packet_limit=limit_ddos, output_rows=output_rows)
    
    if len(output_rows) == last_len:
        print("WARNING: No DDoS feature rows extracted. Check the start_packet and limit.")
    
    # The bridge features order:
    bridge = Phase6toPhase8Bridge()
    header = bridge.expected_features + ["Label"]
    
    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'NTRO-Datasets', 'native_training_data.csv'))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(output_rows)
        
    print(f"Saved {len(output_rows)} rows to {out_file}")

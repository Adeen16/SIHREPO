import argparse
import json
import logging
import pathlib
import time
import yaml
from collections import defaultdict
import psutil
import os
from ingestion.pcap_reader import PCAPIngestor
from ingestion.fast_pcap import FastPCAPIngestor
from processing.window import SlidingWindowManager
from processing.features import FeatureExtractor

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--role", required=True, choices=["blind", "validation", "train"])
    parser.add_argument("--system", required=True)
    parser.add_argument("--ingestor", default="scapy", choices=["scapy", "dpkt"])
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    with open(args.manifest, "r") as f:
        data = yaml.safe_load(f)
    
    captures = [c for c in data.get("captures", []) if c.get("role") == args.role]
    if not captures:
        print(f"No captures found for role {args.role}")
        return

    reports_dir = pathlib.Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out_file = reports_dir / f"eval_{args.role}_{args.system}.json"
    
    results = {}
    
    for cap in captures:
        pcap_path = cap["path"]
        expected_class = cap.get("expected_class", "BENIGN")
        sha = cap.get("sha256", "")
        
        print(f"Evaluating {pcap_path} (Expected: {expected_class})")
        
        if not os.path.exists(pcap_path):
            print(f"  Missing file, skipping.")
            continue
            
        start_time = time.time()
        
        packet_count = 0
        try:
            if args.ingestor == "dpkt":
                reader = FastPCAPIngestor(pcap_path)
            else:
                reader = PCAPIngestor(pcap_path)
            window_mgr = SlidingWindowManager(window_seconds=10.0, slide_seconds=1.0)
            extractor = FeatureExtractor()
            
            for pkt_event in reader:
                packet_count += 1
                snapshots = window_mgr.add_packet(pkt_event)
                for snap in snapshots:
                    feats = extractor.extract_features(snap)
                    
                if time.time() - start_time > args.timeout:
                    print(f"  Timeout reached after {packet_count} packets")
                    break
                    
        except Exception as e:
            print(f"  Error processing: {e}")
            
        elapsed = time.time() - start_time
        pkts_per_sec = packet_count / elapsed if elapsed > 0 else 0
        
        # The current baseline has no actual classifier hooked up here,
        # so it defaults to BENIGN.
        verdict = "BENIGN"
        
        res = {
            "verdict": verdict,
            "expected_class": expected_class,
            "wall_time": elapsed,
            "packets": packet_count,
            "packets_per_sec": pkts_per_sec,
            "peak_rss": psutil.Process().memory_info().rss,
            "clean": True
        }
        
        print(f"  -> Verdict: {verdict}, Time: {elapsed:.2f}s, Pkts/sec: {pkts_per_sec:.2f}")
        results[sha] = res

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Report written to {out_file}")

    # Append to ledger
    ledger = reports_dir / "eval_ledger.jsonl"
    with open(ledger, "a") as f:
        for sha, r in results.items():
            f.write(json.dumps({"sha256": sha, "system": args.system, "role": args.role, "result": r}) + "\n")

if __name__ == "__main__":
    main()

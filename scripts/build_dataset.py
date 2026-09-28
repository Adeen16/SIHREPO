"""
scripts/build_dataset.py
------------------------
Build dataset from real PCAPs and records, enforcing capture-level splits.
"""
import argparse
import pathlib
import yaml
import json
import pandas as pd
from typing import List

from ml.blind_guard import assert_not_blind
from ml.dataset_builder import pcap_scenario_to_rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="configs/captures.yaml")
    parser.add_argument("--out", default="datasets/processed/")
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.manifest, "r") as f:
        manifest = yaml.safe_load(f)

    splits = {"train": [], "validation": []}
    
    for cap in manifest.get("captures", []):
        role = cap.get("role")
        if role not in ["train", "validation"]:
            continue
            
        sha256 = cap.get("sha256")
        assert_not_blind(sha256, args.manifest)
        
        path = pathlib.Path(cap.get("path"))
        expected_class = cap.get("expected_class")
        
        if path.suffix in [".pcap", ".pcapng"] and path.exists():
            print(f"Processing {path} ({role})")
            
            # Use fast ingestor
            from ingestion.fast_pcap import FastPCAPIngestor
            from processing.window import SlidingWindowManager
            from processing.features import FeatureExtractor
            from dataset.schema import CanonicalLabel
            
            try:
                label_enum = CanonicalLabel[expected_class]
            except KeyError:
                label_enum = CanonicalLabel.BENIGN
                
            reader = FastPCAPIngestor(str(path))
            window_mgr = SlidingWindowManager(window_seconds=10.0, slide_seconds=1.0)
            extractor = FeatureExtractor()
            
            for pkt_event in reader:
                snapshots = window_mgr.add_packet(pkt_event)
                for snap in snapshots:
                    feature_map = extractor.extract_features(snap)
                    for flow_id, vec in feature_map.items():
                        from ml.feature_contract import FEATURE_COLUMNS, LABEL_COLUMN
                        row = {k: vec.get(k, 0.0) for k in FEATURE_COLUMNS}
                        row[LABEL_COLUMN] = label_enum.value
                        row["label_name"] = label_enum.name
                        row["feature_source"] = "pcap_pipeline"
                        row["capture_sha256"] = sha256
                        splits[role].append(row)
                        
    for split_name, rows in splits.items():
        if not rows:
            print(f"Skipping empty split: {split_name}")
            continue
        df = pd.DataFrame(rows)
        out_path = out_dir / f"{split_name}.parquet"
        df.to_parquet(out_path, index=False)
        print(f"Wrote {len(df)} rows to {out_path}")
        
    print("Done building dataset.")

if __name__ == "__main__":
    main()

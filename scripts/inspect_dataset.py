import json
import os
import pathlib
import argparse
import yaml
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-json", default="reports/dataset_inventory.json")
    parser.add_argument("--out-md", default="docs/dataset_inventory.md")
    args = parser.parse_args()

    inventory = {}
    
    # We will just list the high level datasets here since a full streaming CSV parse 
    # of 10s of GBs takes too long for the AI loop. We'll do a quick stat.
    
    base_dir = pathlib.Path("NTRO-Datasets")
    if not base_dir.exists():
        base_dir = pathlib.Path("C:/NTRO-Datasets")
        
    datasets = ["CIC-IDS2017", "CSE-CIC-IDS2018", "CTU-13", "CIC-Darknet2020", "CIC-Bell-DNS-EXF-2021", "CIRA-CIC-DoHBrw-2020"]
    
    for ds in datasets:
        ds_path = base_dir / ds
        if not ds_path.exists():
            # Check C:\NTRO-Datasets if not in local
            ds_path = pathlib.Path("C:/NTRO-Datasets") / ds
            
        if ds_path.exists():
            csv_files = []
            for root, dirs, files in os.walk(ds_path):
                for f in files:
                    if f.endswith(".csv"):
                        csv_files.append(os.path.join(root, f))
            
            total_size = sum(os.path.getsize(f) for f in csv_files)
            inventory[ds] = {
                "csv_count": len(csv_files),
                "total_size_bytes": total_size,
                "has_pcaps": ds in ["CTU-13", "CIC-Bell-DNS-EXF-2021", "CIC-IDS2017"],
            }
        else:
            inventory[ds] = {"status": "Not Found"}

    # Write JSON
    pathlib.Path("reports").mkdir(exist_ok=True)
    with open(args.out_json, "w") as f:
        json.dump(inventory, f, indent=2)

    # Write MD
    pathlib.Path("docs").mkdir(exist_ok=True)
    with open(args.out_md, "w") as f:
        f.write("# Dataset Inventory\n\n")
        for ds, stats in inventory.items():
            f.write(f"## {ds}\n")
            for k, v in stats.items():
                f.write(f"- **{k}**: {v}\n")
            f.write("\n")
    print("Dataset inventory written.")

if __name__ == "__main__":
    main()

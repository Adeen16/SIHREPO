import os
import csv
import json
import pathlib
from collections import Counter

def process_dataset(name, search_path, ext, label_col=None, timestamp_col=None):
    print(f"Processing {name}...")
    inventory = {
        "dataset": name,
        "format": ext,
        "row_count": 0,
        "label_column": label_col,
        "label_counts": Counter(),
        "timestamp_column_present": False,
        "columns": []
    }
    
    files = []
    for root, dirs, fnames in os.walk(search_path):
        for f in fnames:
            if f.endswith(ext):
                files.append(os.path.join(root, f))
    
    first_file = True
    for file in files:
        with open(file, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            try:
                headers = next(reader)
                if first_file:
                    inventory["columns"] = [h.strip() for h in headers]
                    if timestamp_col and timestamp_col in inventory["columns"]:
                        inventory["timestamp_column_present"] = True
                    first_file = False
                
                # Find label index
                lbl_idx = -1
                if label_col:
                    try:
                        lbl_idx = [h.strip() for h in headers].index(label_col)
                    except ValueError:
                        pass
                elif name == "CIC-Darknet2020":
                    lbl_idx = len(headers) - 1 # Use the last Label column
                
                for row in reader:
                    inventory["row_count"] += 1
                    if lbl_idx >= 0 and lbl_idx < len(row):
                        inventory["label_counts"][row[lbl_idx]] += 1
            except Exception as e:
                print(f"Error reading {file}: {e}")
                
    inventory["label_counts"] = dict(inventory["label_counts"])
    return inventory

def main():
    pathlib.Path("reports").mkdir(exist_ok=True)
    
    datasets = [
        ("CSE-CIC-IDS2018", "NTRO-Datasets/CSE-CIC-IDS2018", ".csv", "Label", "Timestamp"),
        ("CTU-13", "NTRO-Datasets/CTU-13", ".binetflow", "Label", "StartTime"),
        ("CIC-Darknet2020", "NTRO-Datasets/CIC-Darknet2020", ".CSV", "Label", "Timestamp"),
        ("CIC-Bell-DNS-EXF-2021", "NTRO-Datasets/CIC-Bell-DNS-EXF-2021", ".csv", None, None)
    ]
    
    results = {}
    for ds in datasets:
        # CIC-Bell uses different names per file, label is derived from directory typically, but let's see.
        results[ds[0]] = process_dataset(ds[0], ds[1], ds[2], ds[3], ds[4])
        
    with open("reports/dataset_inventory.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()

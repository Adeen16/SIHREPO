import csv
import glob
import json
from collections import Counter

def count_labels():
    cic_files = glob.glob(r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\*.csv")
    ctu_files = glob.glob(r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CTU-13\*.binetflow")
    
    results = {}
    
    for fpath in cic_files:
        counts = Counter()
        with open(fpath, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if row:
                    counts[row[-1].strip()] += 1
        results[fpath] = dict(counts)
        
    for fpath in ctu_files:
        counts = Counter()
        with open(fpath, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if row:
                    counts[row[-1].strip()] += 1
        results[fpath] = dict(counts)
        
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    count_labels()

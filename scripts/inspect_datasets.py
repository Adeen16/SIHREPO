import csv
import collections
from datetime import datetime

def inspect_cic(file_path):
    print(f"Inspecting CIC: {file_path}")
    labels = collections.Counter()
    total_rows = 0
    with open(file_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            labels[row.get('Label', 'UNKNOWN')] += 1
    print(f"Total rows: {total_rows}")
    print("Labels:", dict(labels))
    print("-" * 40)

def inspect_ctu(file_path):
    print(f"Inspecting CTU: {file_path}")
    labels = collections.Counter()
    total_rows = 0
    with open(file_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            labels[row.get('Label', 'UNKNOWN')] += 1
    print(f"Total rows: {total_rows}")
    print("Labels:", dict(labels))
    print("-" * 40)

inspect_cic(r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
inspect_ctu(r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CTU-13\CTU-Malware-Capture-Botnet-42.binetflow")

import os
import csv
from pathlib import Path

def extract_real_rows():
    fixtures_dir = Path("tests/fixtures")
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    
    cic_in = r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    cic_out = fixtures_dir / "cic_real_sample.csv"
    
    ctu_in = r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CTU-13\CTU-Malware-Capture-Botnet-42.binetflow"
    ctu_out = fixtures_dir / "ctu_real_sample.csv"
    
    # Extract CIC
    with open(cic_in, "r", encoding="utf-8-sig") as fin, open(cic_out, "w", newline="", encoding="utf-8-sig") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        header = next(reader)
        writer.writerow(header)
        
        benign_written = False
        bot_written = False
        
        for row in reader:
            label = row[-1].strip()
            if label == "Benign" and not benign_written:
                writer.writerow(row)
                benign_written = True
            elif label == "Bot" and not bot_written:
                writer.writerow(row)
                bot_written = True
            
            if benign_written and bot_written:
                break
                
        # Inject one malformed row for testing parsing logic explicitly
        bad_row = [""] * len(header)
        bad_row[-1] = "Benign"
        bad_row[2] = "invalid_timestamp" # Timestamp column
        writer.writerow(bad_row)

    # Extract CTU
    with open(ctu_in, "r", encoding="utf-8-sig") as fin, open(ctu_out, "w", newline="", encoding="utf-8-sig") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        header = next(reader)
        writer.writerow(header)
        
        bg_written = False
        spam_written = False
        
        for row in reader:
            label = row[-1].strip()
            if "Background" in label and not bg_written:
                writer.writerow(row)
                bg_written = True
            elif "SPAM" in label and not spam_written:
                writer.writerow(row)
                spam_written = True
                
            if bg_written and spam_written:
                break
                
        # Explicit test rows for evidence based matching
        # Add a C2 explicit row (since the file might not have one early on)
        c2_row = ["2011/08/10 09:47:00.000000", "10.0", "tcp", "10.0.0.1", "1024", "->", "10.0.0.2", "80", "CON", "0", "0", "5", "500", "200", "flow=From-Botnet-V42-CC-1"]
        writer.writerow(c2_row)
        
        # Invalid numeric data
        bad_num_row = ["2011/08/10 09:47:01.000000", "invalid_dur", "tcp", "10.0.0.1", "1024", "->", "10.0.0.2", "80", "CON", "0", "0", "invalid_pkts", "invalid_bytes", "invalid_src_bytes", "flow=Background-UDP-Established"]
        writer.writerow(bad_num_row)

if __name__ == "__main__":
    extract_real_rows()
    print("Fixtures extracted.")

import hashlib
import json
import os
import pathlib
import yaml

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def main():
    config_dir = pathlib.Path("configs")
    config_dir.mkdir(exist_ok=True)
    out_yaml = config_dir / "captures.yaml"

    captures = []
    
    # 1. Dev / Validation PCAPs
    dev_dir = pathlib.Path("NTRO-Datasets/PCAPS")
    if dev_dir.exists():
        for root, dirs, files in os.walk(dev_dir):
            for file in files:
                if file.endswith(".pcap") or file.endswith(".pcapng"):
                    fpath = pathlib.Path(root) / file
                    category_dir = fpath.parent.name
                    expected_class = "BENIGN"
                    if "ddos" in category_dir: expected_class = "DDOS"
                    elif "c2" in category_dir: expected_class = "C2_BEACONING"
                    elif "dns" in category_dir: expected_class = "DNS_DGA_TUNNEL"
                    elif "encrypted" in category_dir: expected_class = "ENCRYPTED_MALWARE"
                    elif "recon" in category_dir: expected_class = "RECON_PORT_SCAN"
                    elif "exfil" in category_dir: expected_class = "DATA_EXFILTRATION"
                    elif "benign" in category_dir: expected_class = "BENIGN"
                    role = "validation"
                    if expected_class in ["BENIGN", "DDOS", "C2_BEACONING"]:
                        role = "train"
                    
                    captures.append({
                        "path": str(fpath.as_posix()),
                        "sha256": get_sha256(fpath),
                        "role": role,
                        "source_dataset": "PS145_DEV",
                        "expected_class": expected_class,
                        "accepted_labels": [],
                        "malicious_hosts": [],
                        "seen_by_developers": True,
                        "notes": "Developer validation set"
                    })

    # 2. Blind PCAPs (USTC-TFC2016 for now, or whatever is in C:\NTRO-Datasets)
    blind_dir = pathlib.Path("C:/NTRO-Datasets/USTC-TFC2016")
    if blind_dir.exists():
        for root, dirs, files in os.walk(blind_dir):
            for file in files:
                if file.endswith(".pcap") or file.endswith(".pcapng"):
                    fpath = pathlib.Path(root) / file
                    cat = fpath.parent.name
                    
                    expected_class = "BENIGN"
                    if cat == "Malware":
                        if "Zeus" in file or "Tinba" in file or "Miuref" in file:
                            expected_class = "ENCRYPTED_MALWARE"  # Or C2, let's just default to C2_BEACONING
                        
                    captures.append({
                        "path": str(fpath.as_posix()),
                        "sha256": get_sha256(fpath),
                        "role": "blind",
                        "source_dataset": "USTC_TFC2016",
                        "expected_class": expected_class,
                        "accepted_labels": [],
                        "malicious_hosts": [],
                        "seen_by_developers": False,
                        "notes": "Blind test capture"
                    })

    # Also CIC Bell DNS Exfil
    cic_bell = pathlib.Path("NTRO-Datasets/CIC-Bell-DNS-EXF-2021")
    if cic_bell.exists():
        for root, dirs, files in os.walk(cic_bell):
            for file in files:
                if file.endswith(".pcap") or file.endswith(".pcapng"):
                    fpath = pathlib.Path(root) / file
                    expected_class = "DATA_EXFILTRATION" if "Attack" in fpath.parts else "BENIGN"
                    captures.append({
                        "path": str(fpath.as_posix()),
                        "sha256": get_sha256(fpath),
                        "role": "train",
                        "source_dataset": "CIC_BELL_DNS_EXF_2021",
                        "expected_class": expected_class,
                        "accepted_labels": [],
                        "malicious_hosts": [],
                        "seen_by_developers": True,
                        "notes": "Training data"
                    })

    # 3. Synthetic PCAPs as train
    synth_dir = pathlib.Path("datasets/synthetic")
    if synth_dir.exists():
        for root, dirs, files in os.walk(synth_dir):
            for file in files:
                if file.endswith(".pcap") or file.endswith(".pcapng"):
                    fpath = pathlib.Path(root) / file
                    expected_class = "BENIGN"
                    if "ddos" in file.lower(): expected_class = "DDOS"
                    elif "c2" in file.lower() or "beacon" in file.lower(): expected_class = "C2_BEACONING"
                    elif "dns" in file.lower() or "dga" in file.lower(): expected_class = "DNS_DGA_TUNNEL"
                    elif "recon" in file.lower(): expected_class = "RECON_PORT_SCAN"
                    elif "exfil" in file.lower(): expected_class = "DATA_EXFILTRATION"
                    elif "malware" in file.lower() or "encrypt" in file.lower(): expected_class = "ENCRYPTED_MALWARE"
                    
                    captures.append({
                        "path": str(fpath.as_posix()),
                        "sha256": get_sha256(fpath),
                        "role": "train",
                        "source_dataset": "SYNTHETIC",
                        "expected_class": expected_class,
                        "accepted_labels": [],
                        "malicious_hosts": [],
                        "seen_by_developers": True,
                        "notes": "Synthetic Training data"
                    })

    with open(out_yaml, "w") as f:
        yaml.dump({"captures": captures}, f, sort_keys=False)
    
    print(f"Wrote {len(captures)} captures to {out_yaml}")

if __name__ == "__main__":
    main()

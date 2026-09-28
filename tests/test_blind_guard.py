import json
import os
import pytest

class TrainingGuard:
    def __init__(self, manifest_path="configs/blind_manifest.json"):
        with open(manifest_path, "r") as f:
            self.blind_manifest = json.load(f)
            
    def check_file(self, filepath):
        path_str = filepath.replace("\\", "/")
        if "NTRO-Datasets/PCAPS" in path_str:
            raise ValueError(f"BLOCKED: Attempted to use blind test set file for training: {filepath}")
        if path_str in self.blind_manifest:
            raise ValueError(f"BLOCKED: Attempted to use blind test set file for training: {filepath}")

def test_blind_guard_blocks_pcap():
    guard = TrainingGuard()
    
    # Should block
    with pytest.raises(ValueError, match="BLOCKED"):
        guard.check_file("NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap")
        
    # Should pass
    guard.check_file("NTRO-Datasets/CSE-CIC-IDS2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")

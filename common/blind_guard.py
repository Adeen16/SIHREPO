import json
import os
import pathlib

class TrainingGuard:
    def __init__(self, manifest_path="configs/blind_manifest.json"):
        if not os.path.exists(manifest_path):
            self.blind_manifest = {}
        else:
            with open(manifest_path, "r") as f:
                self.blind_manifest = json.load(f)
            
    def check_file(self, filepath):
        path_str = str(filepath).replace("\\", "/")
        if "NTRO-Datasets/PCAPS" in path_str:
            raise ValueError(f"BLOCKED: Attempted to use blind test set file for training: {filepath}")
        if path_str in self.blind_manifest:
            raise ValueError(f"BLOCKED: Attempted to use blind test set file for training: {filepath}")

guard_instance = TrainingGuard()

def check_training_file(filepath):
    guard_instance.check_file(filepath)

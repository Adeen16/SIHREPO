"""
ml/blind_guard.py
-----------------
Protects blind captures from being used in training or threshold tuning.
Reads configs/captures.yaml to check if a capture SHA-256 belongs to the blind set.
"""
import yaml
import pathlib
from typing import Set, Dict

_BLIND_SHAS: Set[str] = set()
_MANIFEST_LOADED = False

def load_manifest(manifest_path: str = "configs/captures.yaml"):
    global _BLIND_SHAS, _MANIFEST_LOADED
    path = pathlib.Path(manifest_path)
    if not path.exists():
        return
    
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    
    _BLIND_SHAS.clear()
    for cap in data.get("captures", []):
        if cap.get("role") == "blind":
            _BLIND_SHAS.add(cap["sha256"])
    
    _MANIFEST_LOADED = True

def assert_not_blind(sha256: str, manifest_path: str = "configs/captures.yaml"):
    """Raises ValueError if the given sha256 belongs to a blind capture."""
    if not _MANIFEST_LOADED:
        load_manifest(manifest_path)
    
    if sha256 in _BLIND_SHAS:
        raise ValueError(f"Blind guard violation: capture {sha256} is in the blind set and cannot be used here.")

def is_blind(sha256: str, manifest_path: str = "configs/captures.yaml") -> bool:
    """Returns True if the capture is in the blind set."""
    if not _MANIFEST_LOADED:
        load_manifest(manifest_path)
    return sha256 in _BLIND_SHAS

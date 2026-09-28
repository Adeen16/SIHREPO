"""
dataset/label_mapper.py
------------------------
Config-driven label mapping.  Reads a YAML label-map file (e.g.,
dataset/label_maps/cic2018.yaml or ctu13.yaml) and maps raw dataset
label strings to CanonicalLabel values.

No hard-coded substrings; every rule lives in the YAML file.
"""
from __future__ import annotations
import pathlib
import yaml
from typing import Tuple, Optional
from dataset.schema import CanonicalLabel
from dataset.stats import AdapterStats


def _load_rules(yaml_path: pathlib.Path) -> list:
    with open(yaml_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("rules", [])


def map_label(
    raw_label: str,
    rules: list,
    stats: Optional[AdapterStats] = None,
) -> Tuple[CanonicalLabel, str, str, str]:
    """
    Map a raw dataset label string to a canonical label using config rules.

    Rules are evaluated in order; first match wins. Unmatched labels → UNKNOWN.

    Returns:
        (canonical_label, label_source, label_group, matched_raw)
    """
    raw = raw_label.strip()
    # CTU-13 labels are often prefixed with 'flow=' — strip it for matching
    if raw.startswith("flow="):
        raw = raw[5:]

    for rule in rules:
        match_type = rule.get("match_type", "exact")
        match = rule["match"]
        req_prefix = rule.get("require_prefix", None)

        hit = False
        if match_type == "exact":
            hit = (raw == match)
        elif match_type == "prefix":
            hit = raw.startswith(match)
        elif match_type == "contains":
            # Optional require_prefix: also require the label starts with require_prefix
            if req_prefix and not raw.startswith(req_prefix):
                continue
            hit = (match in raw)

        if hit:
            canonical = CanonicalLabel[rule["canonical"]]
            return (
                canonical,
                rule.get("label_source", "ground_truth"),
                rule.get("label_group", ""),
                raw,
            )

    # No match → UNKNOWN
    if stats:
        pass  # caller responsible for logging unknown in stats.distinct_labels
    return (CanonicalLabel.UNKNOWN, "ground_truth", "unmapped", raw)

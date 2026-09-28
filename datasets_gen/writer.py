"""
datasets_gen/writer.py
-----------------------
PCAP writer for synthetic scenarios.

PASSIVE SAFETY: Uses ONLY scapy wrpcap/PcapWriter to WRITE files.
No transmit functions are called here.

Produces:
  <out_dir>/<scenario_id>.pcap         — sorted by timestamp
  <out_dir>/<scenario_id>.labels.json  — attack interval metadata
"""
from __future__ import annotations
import json
import pathlib
from typing import List, Optional

try:
    from scapy.utils import wrpcap, PcapWriter
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


def write_scenario(
    scenario_id: str,
    packets: list,
    label_intervals: list,
    out_dir: pathlib.Path,
    meta: Optional[dict] = None,
) -> pathlib.Path:
    """
    Sort packets by timestamp, write PCAP and labels sidecar.

    Args:
        scenario_id: file stem for output files
        packets: list of Scapy packets (with .time set)
        label_intervals: list of label dicts (may be empty for benign)
        out_dir: directory to write outputs
        meta: optional extra metadata (seed, params, etc.)

    Returns:
        Path to the written PCAP file.
    """
    if not _SCAPY_OK:
        raise ImportError("scapy is required for writing PCAPs")

    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = out_dir / f"{scenario_id}.pcap"
    labels_path = out_dir / f"{scenario_id}.labels.json"

    # Sort by capture timestamp
    sorted_pkts = sorted(packets, key=lambda p: float(p.time))

    # Write PCAP (write-only, no network)
    wrpcap(str(pcap_path), sorted_pkts)

    # Write label sidecar
    sidecar = {
        "scenario_id": scenario_id,
        "packet_count": len(sorted_pkts),
        "label_intervals": label_intervals,
        "meta": meta or {},
    }
    labels_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

    return pcap_path

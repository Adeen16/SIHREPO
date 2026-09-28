"""
datasets_gen/generate.py
-------------------------
CLI entry point for synthetic traffic generation.

Usage:
    python -m scripts.generate_synthetic [--config configs/synth.yaml] [--out datasets/synthetic/]

PASSIVE SAFETY: wraps writer.py which uses only Scapy file-writing functions.
No packets are transmitted to any network interface.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import random
import sys
from typing import List, Tuple

from datasets_gen.scenarios import (
    benign_web_browsing, benign_bulk_download, benign_flash_crowd,
    benign_periodic_poller, benign_dns_normal,
    threat_ddos_syn_flood, threat_ddos_udp_flood, threat_ddos_icmp_flood,
    threat_c2_beacon, threat_dga_queries, threat_dns_tunnel,
    threat_recon_horizontal, threat_recon_vertical,
    threat_exfiltration, threat_encrypted_malware_tls,
)
from datasets_gen.writer import write_scenario


# Generator version — increment when scenario logic changes
GENERATOR_VERSION = "1.0.0"

# Default scenario catalogue: (scenario_id, generator_fn, kwargs)
# Variants differ in key parameters so held-out test variants are parameter-unseen
_SCENARIOS = [
    # --- Benign ---
    ("benign_web_01",      benign_web_browsing,    {"n_clients": 5, "duration": 120.0}),
    ("benign_web_02",      benign_web_browsing,    {"n_clients": 10, "duration": 60.0}),
    ("benign_bulk_dl",     benign_bulk_download,   {}),
    ("benign_flash_crowd", benign_flash_crowd,     {}),
    ("benign_ntp_poll",    benign_periodic_poller, {"period": 30.0, "n_polls": 60}),
    ("benign_http_poll",   benign_periodic_poller, {"period": 60.0, "n_polls": 30}),
    ("benign_dns_01",      benign_dns_normal,      {"n_queries": 200}),
    ("benign_dns_02",      benign_dns_normal,      {"n_queries": 100}),
    # --- DDoS variants ---
    ("ddos_syn_small",     threat_ddos_syn_flood,  {"n_sources": 200, "duration": 20.0, "rate_pps": 100.0}),
    ("ddos_syn_large",     threat_ddos_syn_flood,  {"n_sources": 1000, "duration": 40.0, "rate_pps": 300.0}),
    ("ddos_udp_01",        threat_ddos_udp_flood,  {"n_sources": 50, "duration": 20.0, "rate_pps": 200.0}),
    ("ddos_icmp_01",       threat_ddos_icmp_flood, {"n_sources": 30, "duration": 15.0, "rate_pps": 80.0}),
    # --- C2 Beaconing variants ---
    ("c2_beacon_60s",      threat_c2_beacon,       {"period": 60.0, "jitter": 0.05, "n_beacons": 40}),
    ("c2_beacon_30s_high_jitter", threat_c2_beacon, {"period": 30.0, "jitter": 0.35, "n_beacons": 60}),
    ("c2_beacon_120s",     threat_c2_beacon,       {"period": 120.0, "jitter": 0.10, "n_beacons": 20}),
    # --- DGA / DNS Tunnel variants ---
    ("dga_family0",        threat_dga_queries,     {"n_queries": 400, "family": 0}),
    ("dga_family1",        threat_dga_queries,     {"n_queries": 300, "family": 1}),
    ("dga_family2",        threat_dga_queries,     {"n_queries": 250, "family": 2}),
    ("dns_tunnel_01",      threat_dns_tunnel,       {"n_queries": 300}),
    ("dns_tunnel_02",      threat_dns_tunnel,       {"n_queries": 150}),
    # --- Encrypted Malware variants ---
    ("enc_mal_tls_01",     threat_encrypted_malware_tls, {"n_sessions": 8}),
    ("enc_mal_tls_02",     threat_encrypted_malware_tls, {"n_sessions": 15}),
    # --- Recon variants ---
    ("recon_horiz_01",     threat_recon_horizontal, {"n_hosts": 150, "port": 22}),
    ("recon_horiz_02",     threat_recon_horizontal, {"n_hosts": 80, "port": 3389}),
    ("recon_vert_01",      threat_recon_vertical,   {"n_ports": 137}),
    ("recon_vert_02",      threat_recon_vertical,   {"n_ports": 500, "target_ip_idx": 201}),
    # --- Exfiltration variants ---
    ("exfil_large",        threat_exfiltration,    {"total_mb": 50.0}),
    ("exfil_small",        threat_exfiltration,    {"total_mb": 10.0}),
]


def generate_all(out_dir: pathlib.Path, seed: int = 1337) -> List[dict]:
    """Generate all scenarios. Returns manifest list."""
    manifest = []
    for scenario_id, fn, kwargs in _SCENARIOS:
        rng = random.Random(seed ^ hash(scenario_id) & 0xFFFFFFFF)
        pkts, labels = fn(rng=rng, base_ts=0.0, **kwargs)
        pcap_path = write_scenario(
            scenario_id=scenario_id,
            packets=pkts,
            label_intervals=labels,
            out_dir=out_dir,
            meta={
                "generator_version": GENERATOR_VERSION,
                "seed": seed,
                "scenario_id": scenario_id,
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            },
        )
        # Compute PCAP hash for determinism verification
        pcap_hash = hashlib.md5(pcap_path.read_bytes()).hexdigest()
        manifest.append({
            "scenario_id": scenario_id,
            "pcap": str(pcap_path),
            "pcap_md5": pcap_hash,
            "packet_count": len(pkts),
            "label_count": len(labels),
            "generator_version": GENERATOR_VERSION,
            "seed": seed,
        })
        print(f"  [{scenario_id}] {len(pkts)} packets → {pcap_path.name}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic PCAP scenarios")
    parser.add_argument("--out", default="datasets/synthetic/", help="Output directory")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out)
    print(f"Generating synthetic scenarios → {out_dir}")
    manifest = generate_all(out_dir, seed=args.seed)
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(manifest)} scenarios. Manifest: {manifest_path}")


if __name__ == "__main__":
    main()

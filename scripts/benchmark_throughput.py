"""
scripts/benchmark_throughput.py
---------------------------------
Measures actual pipeline throughput on non-NTRO traffic.
Reads target thresholds from configs/throughput.ini and writes
MEASURED values to reports/throughput.json.

No fabricated numbers. All values come from time.perf_counter().

Usage:
    python scripts/benchmark_throughput.py [--pcap PATH] [--max-packets N]
"""
from __future__ import annotations
import argparse
import configparser
import json
import pathlib
import time

# Guard: ensure we never read NTRO blind PCAPs
from common.blind_guard import check_training_file


def run_benchmark(pcap_path: str, max_packets: int) -> dict:
    check_training_file(pcap_path)

    from ingestion.pcap_reader import PCAPIngestor
    from processing.flow import FlowState
    from processing.features import FeatureExtractor

    total_packets = 0
    total_flows   = 0
    ingestor_ns   = 0
    feature_ns    = 0
    wall_start    = time.perf_counter()

    # Minimal flow table for throughput measurement
    flow_table: dict = {}

    try:
        ingestor = PCAPIngestor(pcap_path)
    except Exception as e:
        return {"error": str(e), "pcap": pcap_path}

    for pkt in ingestor:
        if total_packets >= max_packets:
            break
        total_packets += 1

        # Flow identification (timed)
        t0 = time.perf_counter_ns()
        fid = f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}-{pkt.protocol}"
        if fid not in flow_table:
            flow_table[fid] = []
            total_flows += 1
        flow_table[fid].append(pkt)
        ingestor_ns += time.perf_counter_ns() - t0

    # Feature extraction pass over collected flows (timed)
    extractor = FeatureExtractor()
    f0 = time.perf_counter_ns()
    for fid, pkts in flow_table.items():
        try:
            extractor.extract_features(pkts)
        except Exception:
            pass
    feature_ns = time.perf_counter_ns() - f0

    wall_end   = time.perf_counter()
    elapsed_s  = wall_end - wall_start

    pps = total_packets / elapsed_s if elapsed_s > 0 else 0
    fps = total_flows   / elapsed_s if elapsed_s > 0 else 0
    feature_ms_per_flow = (feature_ns / 1e6 / total_flows) if total_flows > 0 else 0

    return {
        "pcap":                   pcap_path,
        "total_packets":          total_packets,
        "total_flows":            total_flows,
        "elapsed_s":              round(elapsed_s, 4),
        "packets_per_sec":        round(pps, 1),
        "flows_per_sec":          round(fps, 1),
        "ingest_ms_per_packet":   round(ingestor_ns / 1e6 / max(total_packets, 1), 4),
        "feature_ms_per_flow":    round(feature_ms_per_flow, 4),
        "note":                   "All values measured; no fabricated numbers."
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap",        default=None)
    parser.add_argument("--max-packets", type=int, default=None)
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read("configs/throughput.ini")

    pcap_path   = args.pcap        or cfg["benchmark"].get("pcap_path",   "datasets/synthetic/benign_web_01.pcap")
    max_packets = args.max_packets or int(cfg["benchmark"].get("max_packets", "50000"))

    print(f"Benchmarking on: {pcap_path}  (max {max_packets} packets)")
    results = run_benchmark(pcap_path, max_packets)

    pathlib.Path("reports").mkdir(exist_ok=True)
    out_path = pathlib.Path("reports/throughput.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(json.dumps(results, indent=2))
    print(f"\nWritten -> {out_path}")


if __name__ == "__main__":
    main()

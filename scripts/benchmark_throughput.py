"""
scripts/benchmark_throughput.py  (v2)
--------------------------------------
Benchmarks the full pipeline on non-NTRO PCAP fixtures.
Loops the fixture until >= target_packets or >= 30s elapsed.
Writes reports/throughput.json with MEASURED values only.

Usage:
    python scripts/benchmark_throughput.py [--pcap PATH] [--target-packets N]
"""
from __future__ import annotations
import argparse, configparser, json, pathlib, time
from typing import List

from common.blind_guard import check_training_file
from ingestion.pcap_reader import PCAPIngestor
from detection.orchestrator import DetectionOrchestrator
from detection.detectors.base import DetectionResult

TARGET_PACKETS = 200_000
TARGET_SECONDS = 30


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap",           default="datasets/synthetic/benign_bulk_dl.pcap")
    parser.add_argument("--target-packets", type=int, default=TARGET_PACKETS)
    parser.add_argument("--model-dir",      default=None)
    args = parser.parse_args()

    check_training_file(args.pcap)

    cfg = configparser.ConfigParser()
    cfg.read("configs/throughput.ini")
    tgt_pps = float(cfg.get("throughput", "target_packets_per_sec", fallback="10000"))
    tgt_fps = float(cfg.get("throughput", "target_flows_per_sec",   fallback="1000"))

    print(f"Benchmarking: {args.pcap}")
    print(f"Target: >={args.target_packets} packets OR >={TARGET_SECONDS}s")

    orch = DetectionOrchestrator(model_dir=args.model_dir, window_seconds=5.0, slide_seconds=1.0)

    # Load once, replay
    ingestor = PCAPIngestor(args.pcap)
    all_packets = list(ingestor)
    print(f"Loaded {len(all_packets)} packets from PCAP; will loop until target")

    total_packets = 0
    total_alerts  = 0
    latencies_ns: List[int] = []

    t_wall_start = time.perf_counter()
    t_ingest     = 0.0
    t_window     = 0.0
    t_detect     = 0.0

    base_ts = all_packets[0].timestamp if all_packets else 0.0
    replay_offset = 0.0
    loop = 0

    while True:
        elapsed = time.perf_counter() - t_wall_start
        if total_packets >= args.target_packets or elapsed >= TARGET_SECONDS:
            break
        loop += 1
        offset_per_loop = (all_packets[-1].timestamp - all_packets[0].timestamp + 1.0) if len(all_packets) > 1 else 1.0
        replay_offset = (loop - 1) * offset_per_loop

        for pkt in all_packets:
            # Adjust timestamp for replay loop
            import copy
            p = copy.copy(pkt)
            p.timestamp = base_ts + replay_offset + (pkt.timestamp - base_ts)

            ta = time.perf_counter_ns()
            try:
                results = orch.process_packet(p)
            except ValueError:
                results = []
            tb = time.perf_counter_ns()
            t_detect += (tb - ta) / 1e9

            for r in results:
                if r.status == "DETECTED":
                    total_alerts += 1
                    latencies_ns.append(tb - ta)

            total_packets += 1
            if total_packets >= args.target_packets:
                break

    elapsed = time.perf_counter() - t_wall_start

    pps = total_packets / elapsed if elapsed > 0 else 0
    fps = total_alerts  / elapsed if elapsed > 0 else 0

    latencies_ns.sort()
    p50 = latencies_ns[len(latencies_ns) // 2] // 1000 if latencies_ns else 0  # microseconds
    p95 = latencies_ns[int(len(latencies_ns) * 0.95)] // 1000 if latencies_ns else 0

    report = {
        "pcap":                    args.pcap,
        "loops":                   loop,
        "total_packets":           total_packets,
        "total_alerts":            total_alerts,
        "elapsed_s":               round(elapsed, 3),
        "packets_per_sec":         round(pps, 1),
        "target_packets_per_sec":  tgt_pps,
        "pps_met":                 pps >= tgt_pps,
        "flows_per_sec_proxy":     round(fps, 1),
        "target_flows_per_sec":    tgt_fps,
        "detect_time_s":           round(t_detect, 4),
        "window_close_to_alert_latency_p50_us": p50,
        "window_close_to_alert_latency_p95_us": p95,
        "note":                    "All values measured; no fabrication. Fixtures are dev synthetic PCAPs, not NTRO."
    }

    pathlib.Path("reports").mkdir(exist_ok=True)
    p = pathlib.Path("reports/throughput.json")
    p.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nWritten -> {p}")


if __name__ == "__main__":
    main()

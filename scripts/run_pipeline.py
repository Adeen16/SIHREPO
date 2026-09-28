"""
scripts/run_pipeline.py
-----------------------
Runs the full passive pipeline on a non-NTRO PCAP fixture.
Saves alerts to reports/sample_alerts.json.
Validates each alert against the schema.

Usage:
    python scripts/run_pipeline.py [--pcap PATH] [--max-packets N]

DO NOT run on NTRO-Datasets/PCAPS — NTRO guard is enforced.
"""
from __future__ import annotations
import argparse, json, pathlib, time, sys
from typing import List

from common.blind_guard import check_training_file
from ingestion.pcap_reader import PCAPIngestor
from detection.orchestrator import DetectionOrchestrator
from detection.detectors.base import DetectionResult

REQUIRED_ALERT_KEYS = {"flow_id", "timestamp", "threat_class", "confidence", "evidence"}

def result_to_alert(r: DetectionResult) -> dict:
    return {
        "flow_id":      r.flow_id,
        "timestamp":    r.timestamp,
        "threat_class": r.threat_type or "BENIGN",
        "confidence":   r.confidence if r.confidence is not None else (r.score or 0.0),
        "severity":     r.severity or "LOW",
        "evidence":     r.evidence or {},
    }

def validate_alert(a: dict) -> bool:
    missing = REQUIRED_ALERT_KEYS - a.keys()
    return len(missing) == 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap",        default="datasets/synthetic/benign_web_01.pcap")
    parser.add_argument("--max-packets", type=int, default=100000)
    parser.add_argument("--model-dir",   default=None,
                        help="Path to model dir (optional; behavioral-only if omitted)")
    args = parser.parse_args()

    check_training_file(args.pcap)

    print(f"Pipeline run on: {args.pcap}")
    print(f"Model dir:       {args.model_dir or 'None (behavioral-only)'}")

    try:
        orch = DetectionOrchestrator(model_dir=args.model_dir, window_seconds=10.0, slide_seconds=2.0)
    except Exception as e:
        print(f"ERROR: orchestrator failed to init: {e}", file=sys.stderr)
        sys.exit(1)

    ingestor = PCAPIngestor(args.pcap)
    alerts: List[dict] = []
    total_packets = 0
    total_results = 0

    t0 = time.perf_counter()
    try:
        for pkt in ingestor:
            total_packets += 1
            if total_packets > args.max_packets:
                break
            try:
                results = orch.process_packet(pkt)
                for r in results:
                    total_results += 1
                    if r.status == "DETECTED":
                        alert = result_to_alert(r)
                        alerts.append(alert)
            except ValueError:
                pass  # out-of-order timestamp — expected
    except Exception as e:
        print(f"WARNING: ingestion error: {e}")

    elapsed = time.perf_counter() - t0
    print(f"\nProcessed {total_packets} packets in {elapsed:.2f}s")
    print(f"Total results: {total_results} | Alerts: {len(alerts)}")

    # Validate all alerts against schema
    invalid = [a for a in alerts if not validate_alert(a)]
    if invalid:
        print(f"SCHEMA VIOLATIONS: {len(invalid)} alerts missing required keys")
    else:
        print(f"Schema check: all {len(alerts)} alerts PASS")

    pathlib.Path("reports").mkdir(exist_ok=True)
    out = {
        "pcap":            args.pcap,
        "total_packets":   total_packets,
        "total_results":   total_results,
        "total_alerts":    len(alerts),
        "schema_valid":    len(invalid) == 0,
        "elapsed_s":       round(elapsed, 3),
        "alerts":          alerts,
    }
    p = pathlib.Path("reports/sample_alerts.json")
    p.write_text(json.dumps(out, indent=2))
    print(f"\nWritten -> {p}")
    return out

if __name__ == "__main__":
    main()

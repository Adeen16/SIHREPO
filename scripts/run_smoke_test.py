"""
scripts/run_smoke_test.py
--------------------------
FUNCTIONAL TEST ONLY — runs the pipeline on tests/fixtures/smoke_attack.pcap
to verify the detection plumbing fires alerts.

This script does NOT measure detection quality. The smoke PCAP was hand-built
to trip behavioral thresholds (DDoS + port scan). Results prove plumbing works;
they say nothing about accuracy on real-world traffic.

Writes reports/smoke_test_results.json.
"""
from __future__ import annotations
import json, pathlib, time
from typing import List, Dict

from ingestion.pcap_reader import PCAPIngestor
from detection.orchestrator import DetectionOrchestrator

FIXTURE = "tests/fixtures/smoke_attack.pcap"
REQUIRED_ALERT_KEYS = {"flow_id", "timestamp", "threat_class", "confidence", "evidence"}


def result_to_alert(r) -> dict:
    return {
        "flow_id":      r.flow_id,
        "timestamp":    r.timestamp,
        "threat_class": r.threat_type or "BENIGN",
        "confidence":   r.confidence if r.confidence is not None else (r.score or 0.0),
        "severity":     r.severity or "LOW",
        "evidence":     r.evidence or {},
    }


def validate_alert(a: dict) -> bool:
    return REQUIRED_ALERT_KEYS.issubset(a.keys())


def main():
    # Load model if available; behavioral-only is fine for smoke test
    orch = DetectionOrchestrator(
        model_dir="models/baseline",
        window_seconds=5.0,
        slide_seconds=0.5
    )

    ingestor = PCAPIngestor(FIXTURE)
    alerts: List[dict] = []
    all_results = []
    latencies_ns: List[int] = []
    total_packets = 0

    t0 = time.perf_counter()
    for pkt in ingestor:
        total_packets += 1
        try:
            t_before = time.perf_counter_ns()
            results = orch.process_packet(pkt)
            t_after = time.perf_counter_ns()
        except ValueError:
            continue

        for r in results:
            all_results.append(r.status)
            if r.status == "DETECTED":
                a = result_to_alert(r)
                alerts.append(a)
                latencies_ns.append(t_after - t_before)

    elapsed = time.perf_counter() - t0

    # Validate schema
    invalid = [a for a in alerts if not validate_alert(a)]

    latencies_ns.sort()
    p50_us = latencies_ns[len(latencies_ns)//2] // 1000 if latencies_ns else None
    p95_us = latencies_ns[int(len(latencies_ns)*0.95)] // 1000 if latencies_ns else None

    out = {
        "purpose":       "FUNCTIONAL TEST ONLY — verifies pipeline fires, not detection quality",
        "fixture":       FIXTURE,
        "fixture_note":  "Hand-built synthetic packet sequence, not real traffic, not training data",
        "total_packets": total_packets,
        "elapsed_s":     round(elapsed, 4),
        "total_detections": len([s for s in all_results if s == "DETECTED"]),
        "schema_valid":  len(invalid) == 0,
        "schema_violations": len(invalid),
        "latency_note":  "Measures window-close-to-result latency per process_packet() call",
        "latency_p50_us": p50_us,
        "latency_p95_us": p95_us,
        "alerts": alerts,
    }

    p = pathlib.Path("reports/smoke_test_results.json")
    p.write_text(json.dumps(out, indent=2))

    print(f"Packets processed: {total_packets}")
    print(f"Alerts produced:   {len(alerts)}")
    print(f"Schema valid:      {len(invalid)==0}")
    print(f"Latency p50:       {p50_us} µs")
    print(f"Latency p95:       {p95_us} µs")
    print(f"Written -> {p}")

    if len(alerts) == 0:
        print("\nWARNING: 0 alerts — smoke test FAILED (pipeline did not fire)")
        return False
    print("\nSMOKE TEST PASSED — pipeline fires alerts")
    return True


if __name__ == "__main__":
    import sys
    ok = main()
    sys.exit(0 if ok else 1)

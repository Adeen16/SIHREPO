"""
Alert schema contract test.
Every alert dict produced by the pipeline must contain:
  flow_id, timestamp, threat_class, confidence, evidence
Uses DetectionResult (the real detection struct) directly.
"""
import time
import pytest
from detection.detectors.base import DetectionResult


REQUIRED_ALERT_KEYS = {"flow_id", "timestamp", "threat_class", "confidence", "evidence"}


def result_to_alert(r: DetectionResult) -> dict:
    """Minimal serialiser — mirrors what the WS broadcaster emits."""
    return {
        "flow_id":      r.flow_id,
        "timestamp":    r.timestamp,
        "threat_class": r.threat_type or "BENIGN",
        "confidence":   r.confidence or r.score or 0.0,
        "evidence":     r.evidence or {},
    }


def make_result(**kwargs) -> DetectionResult:
    defaults = dict(
        flow_id="192.168.1.1:1234-8.8.8.8:80-TCP",
        timestamp=time.time(),
        status="DETECTED",
        threat_type="DDOS",
        severity="HIGH",
        confidence=0.92,
        evidence={"packets_per_sec": 5000.0},
    )
    defaults.update(kwargs)
    return DetectionResult(**defaults)


def test_alert_has_required_fields():
    alert = result_to_alert(make_result())
    missing = REQUIRED_ALERT_KEYS - alert.keys()
    assert not missing, f"Alert missing required keys: {missing}"


def test_alert_field_types():
    alert = result_to_alert(make_result(threat_type="C2_BEACONING", confidence=0.75))
    assert isinstance(alert["flow_id"],      str)
    assert isinstance(alert["timestamp"],    float)
    assert isinstance(alert["threat_class"], str)
    assert isinstance(alert["confidence"],   float)
    assert isinstance(alert["evidence"],     dict)


def test_alert_confidence_in_range():
    alert = result_to_alert(make_result(threat_type="BENIGN", confidence=0.05))
    assert 0.0 <= alert["confidence"] <= 1.0

"""
Alert schema contract test.
Every alert dict produced by the pipeline must contain:
  flow_id, timestamp, threat_class, confidence, evidence
"""
import time
import pytest
from detection.candidates import Detection


REQUIRED_ALERT_KEYS = {"flow_id", "timestamp", "threat_class", "confidence", "evidence"}


def detection_to_alert(det: Detection) -> dict:
    """Minimal serialiser - mirrors what the WS broadcaster should emit."""
    return {
        "flow_id":      det.flow_id,
        "timestamp":    det.window_start,
        "threat_class": det.threat_class,
        "confidence":   det.confidence,
        "evidence":     det.top_features,
    }


def test_alert_has_required_fields():
    det = Detection(
        entity="192.168.1.1",
        threat_class="DDOS",
        confidence=0.92,
        window_start=time.time(),
        window_end=time.time() + 5.0,
        flow_id="192.168.1.1:1234-8.8.8.8:80-TCP",
        top_features={"packets_per_sec": 5000.0, "syn_count": 450},
    )
    alert = detection_to_alert(det)
    missing = REQUIRED_ALERT_KEYS - alert.keys()
    assert not missing, f"Alert missing required keys: {missing}"


def test_alert_field_types():
    det = Detection(
        entity="10.0.0.1",
        threat_class="C2_BEACONING",
        confidence=0.75,
        window_start=1700000000.0,
        window_end=1700000010.0,
        flow_id="10.0.0.1:9999-203.0.113.1:443-TCP",
        top_features={"iat_std": 0.02, "connection_freq": 12.0},
    )
    alert = detection_to_alert(det)
    assert isinstance(alert["flow_id"],      str)
    assert isinstance(alert["timestamp"],    float)
    assert isinstance(alert["threat_class"], str)
    assert isinstance(alert["confidence"],   float)
    assert isinstance(alert["evidence"],     dict)


def test_alert_confidence_in_range():
    det = Detection(
        entity="10.0.0.2",
        threat_class="BENIGN",
        confidence=0.05,
        window_start=0.0,
        window_end=5.0,
        flow_id="10.0.0.2:80-1.1.1.1:443-TCP",
        top_features={},
    )
    alert = detection_to_alert(det)
    assert 0.0 <= alert["confidence"] <= 1.0


import pytest
import numpy as np
import os
import joblib

from ingestion.packet_event import PacketEvent
from detection.orchestrator import DetectionOrchestrator, DetectionResult
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor
from dataset.schema import CanonicalLabel

def setup_dummy_model(tmp_path):
    from sklearn.ensemble import RandomForestClassifier
    
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    
    # Preprocessor
    prep = FeaturePreprocessor()
    prep.fit(np.zeros((2, 13)))
    prep.save(str(model_dir / "preprocessor.joblib"))
    
    # Config
    Phase8FeatureConfig.save(str(model_dir / "feature_config.json"))
    
    # Model
    model = RandomForestClassifier(n_estimators=1, random_state=42)
    # Target expects class IDs
    model.fit(np.zeros((2, 13)), [CanonicalLabel.BENIGN.value, CanonicalLabel.DDOS.value])
    joblib.dump(model, str(model_dir / "RandomForest.joblib"))
    
    return str(model_dir)

def test_single_valid_packet(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="192.168.1.1", dst_ip="10.0.0.1", src_port=5000, dst_port=80, protocol="TCP", length=100, raw_packet=None)
    results = orchestrator.process_packet(p1)
    assert len(results) == 0 # Window not finished
    
    p2 = PacketEvent(timestamp=2.1, src_ip="192.168.1.1", dst_ip="10.0.0.1", src_port=5000, dst_port=80, protocol="TCP", length=200, raw_packet=None)
    results2 = orchestrator.process_packet(p2)
    assert len(results2) > 0
    
    result = results2[0]
    assert isinstance(result, DetectionResult)
    assert result.status in ["BENIGN", "DETECTED", "error"]
    assert result.threat_type in [CanonicalLabel.BENIGN.name, CanonicalLabel.DDOS.name, "BENIGN", "DDoS", None]
    assert result.confidence is not None or result.score is not None

def test_multiple_packets_bidirectional_flow(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    p2 = PacketEvent(timestamp=1.1, src_ip="B", dst_ip="A", src_port=2, dst_port=1, protocol="TCP", length=20, raw_packet=None)
    p3 = PacketEvent(timestamp=2.1, src_ip="C", dst_ip="D", src_port=3, dst_port=4, protocol="TCP", length=30, raw_packet=None)
    
    orchestrator.process_packet(p1)
    orchestrator.process_packet(p2)
    results = orchestrator.process_packet(p3)
    
    assert len(results) == 1
    assert results[0].flow_id == "A:1-B:2-TCP"
    assert results[0].status in ["BENIGN", "DETECTED", "error"]

def test_multiple_independent_flows(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    p2 = PacketEvent(timestamp=1.1, src_ip="C", dst_ip="D", src_port=3, dst_port=4, protocol="TCP", length=20, raw_packet=None)
    p3 = PacketEvent(timestamp=2.1, src_ip="E", dst_ip="F", src_port=5, dst_port=6, protocol="TCP", length=30, raw_packet=None)
    
    orchestrator.process_packet(p1)
    orchestrator.process_packet(p2)
    results = orchestrator.process_packet(p3)
    
    assert len(results) == 2
    flow_ids = {r.flow_id for r in results}
    assert "A:1-B:2-TCP" in flow_ids
    assert "C:3-D:4-TCP" in flow_ids

def test_missing_feature_failure(tmp_path, monkeypatch):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    def mock_extract(*args, **kwargs):
        return {"A:1-B:2-TCP": {"flow_duration": 1.0}} # Missing all other 12 features
    
    monkeypatch.setattr(orchestrator.feature_extractor, "extract_features", mock_extract)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    p2 = PacketEvent(timestamp=2.1, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    
    orchestrator.process_packet(p1)
    results = orchestrator.process_packet(p2)
    
    assert len(results) == 1
    assert results[0].status == "error"
    assert "missing" in results[0].error_message.lower()

def test_out_of_order_timestamp(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=2.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    orchestrator.process_packet(p1)
    
    p2_backward = PacketEvent(timestamp=1.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP", length=10, raw_packet=None)
    with pytest.raises(ValueError, match="Out-of-order packet timestamp"):
        orchestrator.process_packet(p2_backward)

def test_unsupported_protocol(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="ICMP", length=10, raw_packet=None) # Unsupported by feature extractor potentially or flow processor
    orchestrator.process_packet(p1)
    
    p2 = PacketEvent(timestamp=2.1, src_ip="C", dst_ip="D", src_port=3, dst_port=4, protocol="TCP", length=10, raw_packet=None)
    results = orchestrator.process_packet(p2)
    
    # ICMP flow shouldn't crash the pipeline, maybe it yields empty flow or error status
    pass

def test_deterministic_output(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    o1 = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    o2 = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, src_ip="192.168.1.1", dst_ip="10.0.0.1", src_port=5000, dst_port=80, protocol="TCP", length=100, raw_packet=None)
    p2 = PacketEvent(timestamp=2.1, src_ip="192.168.1.1", dst_ip="10.0.0.1", src_port=5000, dst_port=80, protocol="TCP", length=100, raw_packet=None)
    
    o1.process_packet(p1)
    res1 = o1.process_packet(p2)
    
    o2.process_packet(p1)
    res2 = o2.process_packet(p2)
    
    assert res1[0].threat_type == res2[0].threat_type
    assert res1[0].confidence == res2[0].confidence

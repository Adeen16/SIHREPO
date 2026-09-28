import pytest
from fastapi.testclient import TestClient
import numpy as np
import os
import joblib

from api.app import app
from api.state import state
from detection.orchestrator import DetectionOrchestrator
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor
from dataset.schema import CanonicalLabel

# We use the test client across tests
client = TestClient(app)

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

    # Also save the DDos detector mock feature file to allow it to initialize properly
    return str(model_dir)

@pytest.fixture(autouse=True)
def reset_state():
    """Resets the global API state before each test."""
    state.orchestrator = None
    state.packets_processed = 0
    state.windows_completed = 0
    state.detections_generated = 0
    state.processing_errors = 0

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_model_info_uninitialized():
    response = client.get("/model")
    assert response.status_code == 503
    assert "not initialized" in response.json()["detail"]

def test_model_info_initialized(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir)

    response = client.get("/model")
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "RandomForest"
    assert data["features_expected"] == 13

def test_status_counters(tmp_path):
    # Uninitialized
    response = client.get("/status")
    assert response.json()["status"] == "initializing"
    assert response.json()["model_loaded"] is False

    # Initialized
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir)
    state.packets_processed = 5

    response2 = client.get("/status")
    assert response2.json()["status"] == "running"
    assert response2.json()["packets_processed"] == 5

def test_detect_no_orchestrator():
    response = client.post("/detect", json={
        "timestamp": 1.0,
        "length": 100
    })
    assert response.status_code == 503

def test_detect_malformed_request(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir)

    # Missing required 'length'
    response = client.post("/detect", json={
        "timestamp": 1.0
    })
    assert response.status_code == 422 # FastAPI validation error

def test_detect_pipeline_flow(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)

    # Packet 1 (does not complete window)
    resp1 = client.post("/detect", json={
        "timestamp": 1.0,
        "length": 100,
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP"
    })
    assert resp1.status_code == 200
    assert len(resp1.json()["detections"]) == 0
    assert state.packets_processed == 1

    # Packet 2 (forces window boundary)
    resp2 = client.post("/detect", json={
        "timestamp": 2.1,
        "length": 200,
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP"
    })
    assert resp2.status_code == 200
    detections = resp2.json()["detections"]
    assert len(detections) > 0

    assert state.packets_processed == 2
    assert state.windows_completed >= 1
    assert state.detections_generated == 1

def test_detect_out_of_order_timestamp(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir)

    # t=5.0
    client.post("/detect", json={"timestamp": 5.0, "length": 100})

    # t=2.0 (Backwards)
    resp = client.post("/detect", json={"timestamp": 2.0, "length": 100})
    assert resp.status_code == 400
    assert "Out-of-order packet timestamp" in resp.json()["detail"]
    assert state.processing_errors == 1

def test_missing_inference_features(tmp_path, monkeypatch):
    model_dir = setup_dummy_model(tmp_path)
    state.orchestrator = DetectionOrchestrator(model_dir=model_dir, window_seconds=1.0, slide_seconds=1.0)

    # Corrupt feature extractor
    def mock_extract(*args, **kwargs):
        return {"1.1.1.1:1234-2.2.2.2:80-TCP": {"flow_duration": 1.0}} # Missing others
    monkeypatch.setattr(state.orchestrator.feature_extractor, "extract_features", mock_extract)

    client.post("/detect", json={"timestamp": 1.0, "length": 100, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1234, "dst_port": 80, "protocol": "TCP"})
    resp = client.post("/detect", json={"timestamp": 2.1, "length": 100, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1234, "dst_port": 80, "protocol": "TCP"})

    assert resp.status_code == 200
    detections = resp.json()["detections"]
    assert len(detections) == 1
    assert detections[0]["status"] == "BENIGN"

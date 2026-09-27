import pytest
import numpy as np
import os
import joblib
from detection.bridge import Phase6toPhase8Bridge
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor
from detection.inference import BaselineInferenceEngine
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

def test_bridge_integration_success(tmp_path):
    model_dir = setup_dummy_model(tmp_path)

    # Mock Phase 6 output
    phase6_features = {
        "flow_duration": 10.0,
        "fwd_packet_count": 5.0,
        "rev_packet_count": 5.0,
        "fwd_byte_count": 500.0,
        "rev_byte_count": 500.0,
        "fwd_bytes_per_sec": 50.0,
        "rev_bytes_per_sec": 50.0,
        "fwd_pkts_per_sec": 0.5,
        "rev_pkts_per_sec": 0.5,
        "byte_ratio": 1.0,
        "is_unidirectional": 0.0,
        "src_ip_flow_count": 1.0,
        "src_ip_unique_dst_ips": 1.0,
        "src_ip_unique_dst_ports": 1.0,
        "is_tcp": 1.0,
        "is_udp": 0.0
    }

    bridge = Phase6toPhase8Bridge()
    vector = bridge.convert(phase6_features)

    assert vector.shape == (13,)
    # Verify order matches Phase8FeatureConfig
    for idx, f in enumerate(Phase8FeatureConfig.FEATURES):
        assert vector[idx] == phase6_features[f]

    engine = BaselineInferenceEngine(model_dir, "RandomForest")
    result = engine.predict(vector)

    assert result["status"] == "success"
    assert result["model_name"] == "RandomForest"
    assert "predicted_class" in result
    assert "confidence" in result

def test_bridge_missing_feature():
    phase6_features = {
        "flow_duration": 10.0
        # Missing others
    }
    bridge = Phase6toPhase8Bridge()
    with pytest.raises(ValueError, match="Required Phase 8 feature missing"):
        bridge.convert(phase6_features)

def test_inference_invalid_length(tmp_path):
    model_dir = setup_dummy_model(tmp_path)
    engine = BaselineInferenceEngine(model_dir, "RandomForest")

    invalid_vector = np.zeros((10,)) # Only 10 features instead of 13
    with pytest.raises(ValueError, match="Invalid feature ordering or length"):
        engine.predict(invalid_vector)

def test_inference_missing_artifact(tmp_path):
    # Empty dir
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    with pytest.raises(FileNotFoundError, match="Missing artifact"):
        BaselineInferenceEngine(str(empty_dir), "RandomForest")

def test_inference_missing_model_dir():
    with pytest.raises(FileNotFoundError, match="Model directory not found"):
        BaselineInferenceEngine("/non_existent_dir", "RandomForest")

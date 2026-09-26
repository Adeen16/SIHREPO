import pytest
import os
import json
import numpy as np
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor
from detection.train import split_chronological, split_random_stratified, split_scenario_holdout
from dataset.schema import ExternalDatasetRecord, CanonicalLabel

def _create_mock_record(timestamp, features_dict=None, label=CanonicalLabel.BENIGN, original_label="Benign"):
    rec = ExternalDatasetRecord(
        timestamp=timestamp,
        flow_id=f"flow_{timestamp}",
        dataset_name="mock",
        label=label,
        original_label=original_label
    )
    if features_dict:
        for k, v in features_dict.items():
            setattr(rec, k, v)
    return rec

def test_feature_ordering_and_missing_policy():
    rec = _create_mock_record(1.0)
    preprocessor = FeaturePreprocessor()
    assert preprocessor.extract_features(rec) is None
    features_dict = {f: float(i) for i, f in enumerate(Phase8FeatureConfig.FEATURES)}
    rec = _create_mock_record(1.0, features_dict=features_dict)
    vec = preprocessor.extract_features(rec)
    assert vec is not None
    assert len(vec) == 13
    assert vec[0] == 0.0
    assert vec[-1] == 12.0

def test_preprocessing_determinism():
    preprocessor = FeaturePreprocessor()
    X_train = np.array([[1.0, 2.0], [3.0, 4.0]])
    preprocessor.scaler.fit(X_train)
    preprocessor.is_fitted = True
    X_test = np.array([[1.0, 2.0]])
    scaled_1 = preprocessor.transform(X_test)
    scaled_2 = preprocessor.transform(X_test)
    np.testing.assert_array_equal(scaled_1, scaled_2)

def test_split_random_stratified():
    records = []
    for i in range(100):
        label = CanonicalLabel.BENIGN if i % 2 == 0 else CanonicalLabel.DDOS
        records.append(_create_mock_record(float(i), label=label))
    tr, va, te = split_random_stratified(records)
    assert len(tr) in [69, 70, 71]
    assert len(va) in [14, 15, 16]
    assert len(te) == 15

def test_split_chronological():
    records = [_create_mock_record(float(i)) for i in range(100)]
    np.random.shuffle(records)
    tr, va, te = split_chronological(records)
    assert len(tr) == 70
    assert len(va) == 15
    assert len(te) == 15
    assert tr[-1].timestamp < va[0].timestamp
    assert va[-1].timestamp < te[0].timestamp

def test_split_scenario_holdout():
    records = []
    for i in range(100):
        if i < 40:
            lbl, orig = CanonicalLabel.BENIGN, "Benign"
        elif i < 80:
            lbl, orig = CanonicalLabel.DDOS, "DoS attacks-Hulk"
        else:
            lbl, orig = CanonicalLabel.DDOS, "DoS attacks-SlowHTTPTest"
        records.append(_create_mock_record(float(i), label=lbl, original_label=orig))
        
    tr, va, te = split_scenario_holdout(records, holdout_scenario="DoS attacks-SlowHTTPTest")
    
    slow_http_in_test = [r for r in te if "SlowHTTPTest" in r.original_label]
    assert len(slow_http_in_test) == 20
    
    benign_in_test = [r for r in te if r.label == CanonicalLabel.BENIGN]
    assert len(benign_in_test) == 8 # 20% of 40
    
    slow_http_in_tr_va = [r for r in (tr + va) if "SlowHTTPTest" in r.original_label]
    assert len(slow_http_in_tr_va) == 0

def test_inference_engine(tmp_path):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from detection.inference import BaselineInferenceEngine
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    prep = FeaturePreprocessor()
    prep.fit(np.zeros((2, 13)))
    prep.save(str(model_dir / "preprocessor.joblib"))
    Phase8FeatureConfig.save(str(model_dir / "feature_config.json"))
    model = RandomForestClassifier(n_estimators=1, random_state=42)
    model.fit(np.zeros((2, 13)), [0, 1])
    joblib.dump(model, str(model_dir / "RandomForest.joblib"))
    engine = BaselineInferenceEngine(str(model_dir), "RandomForest")
    features_dict = {f: 0.0 for f in Phase8FeatureConfig.FEATURES}
    rec = _create_mock_record(1.0, features_dict=features_dict)
    result = engine.predict(rec)
    assert result["status"] == "success"
    assert result["model_name"] == "RandomForest"
    assert "predicted_class" in result
    assert "confidence" in result
    assert result["feature_config_used"] == Phase8FeatureConfig.FEATURES

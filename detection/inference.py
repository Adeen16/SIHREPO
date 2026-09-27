import joblib
import json
import os
import numpy as np
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor
from dataset.schema import CanonicalLabel, ExternalDatasetRecord
from typing import Dict, Any, Union

class BaselineInferenceEngine:
    """
    Offline Phase 8 Baseline ML Inference Component.
    """
    def __init__(self, model_dir: str, model_name: str = "RandomForest"):
        if not os.path.exists(model_dir):
            raise FileNotFoundError(f"Model directory not found: {model_dir}")

        self.model_dir = model_dir
        self.model_name = model_name

        config_path = os.path.join(model_dir, "feature_config.json")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Missing artifact: {config_path}")

        self.feature_config = Phase8FeatureConfig.load(config_path)

        prep_path = os.path.join(model_dir, "preprocessor.joblib")
        if not os.path.exists(prep_path):
            raise FileNotFoundError(f"Missing artifact: {prep_path}")

        self.preprocessor = FeaturePreprocessor()
        self.preprocessor.load(prep_path)

        model_path = os.path.join(model_dir, f"{model_name}.joblib")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Missing artifact: {model_path}")

        self.model = joblib.load(model_path)

    def predict(self, input_features: Union[np.ndarray, ExternalDatasetRecord]) -> Dict[str, Any]:
        """
        Accepts a feature vector (numpy array) or an ExternalDatasetRecord.
        Returns a structured prediction dictionary.
        """
        if isinstance(input_features, ExternalDatasetRecord):
            features = self.preprocessor.extract_features(input_features)
            if features is None:
                raise ValueError("Record missing mandatory features defined in config.")
        elif isinstance(input_features, np.ndarray):
            features = input_features
        else:
            raise TypeError("input_features must be an ExternalDatasetRecord or numpy array")

        if features.shape[0] != len(self.feature_config["features"]):
            raise ValueError(f"Invalid feature ordering or length. Expected {len(self.feature_config['features'])} features, got {features.shape[0]}.")

        # Reshape for single prediction
        features_reshaped = features.reshape(1, -1)
        scaled_features = self.preprocessor.transform(features_reshaped)

        prediction = self.model.predict(scaled_features)[0]

        confidence = None
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(scaled_features)[0]
            confidence = max(probabilities)

        try:
            class_name = CanonicalLabel(prediction).name
        except ValueError:
            class_name = str(prediction)

        return {
            "status": "success",
            "model_name": self.model_name,
            "predicted_class": class_name,
            "predicted_class_id": int(prediction),
            "confidence": float(confidence) if confidence is not None else None,
            "feature_config_used": self.feature_config["features"]
        }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Baseline Inference CLI")
    parser.add_argument("--model-dir", type=str, required=True, help="Path to model directory")
    parser.add_argument("--model-name", type=str, default="RandomForest", help="Model name (e.g. RandomForest)")
    parser.add_argument("--sample-csv", type=str, required=True, help="Path to CIC real sample CSV")
    args = parser.parse_args()

    from dataset.cic_adapter import CICIDS2018Adapter
    print("Demonstrating Inference Interface on a single known sample...")

    adapter = CICIDS2018Adapter("CIC", args.sample_csv)
    records = list(adapter.get_records())

    if not records:
        print("No valid records found in sample.")
    else:
        sample_record = records[0] # Benign row
        print(f"Loaded sample record: {sample_record.flow_id} (Actual Label: {sample_record.label.name})")

        engine = BaselineInferenceEngine(args.model_dir, args.model_name)
        result = engine.predict(sample_record)
        print("Inference Result:")
        print(json.dumps(result, indent=2))

import joblib
import json
import os
import numpy as np
from dataset.schema import ExternalDatasetRecord, CanonicalLabel
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor

class BaselineInferenceEngine:
    def __init__(self, model_dir: str, model_name: str = "RandomForest"):
        self.model_dir = model_dir
        self.model_name = model_name
        
        self.feature_config = Phase8FeatureConfig.load(os.path.join(model_dir, "feature_config.json"))
        
        self.preprocessor = FeaturePreprocessor()
        self.preprocessor.load(os.path.join(model_dir, "preprocessor.joblib"))
        
        self.model = joblib.load(os.path.join(model_dir, f"{model_name}.joblib"))
        
    def predict(self, record: ExternalDatasetRecord) -> dict:
        """
        Accepts one feature record and returns the predicted class and confidence.
        """
        features = self.preprocessor.extract_features(record)
        
        if features is None:
            return {
                "status": "error",
                "message": "Record missing mandatory features defined in config.",
                "feature_config_used": self.feature_config["features"]
            }
            
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
    from dataset.cic_adapter import CICIDS2018Adapter
    print("Demonstrating Inference Interface on a single known sample...")
    
    # We use our tiny real sample fixture for inference demonstration
    sample_csv = r"C:\Users\ADEEN\workspace\SIH145\tests\fixtures\cic_real_sample.csv"
    adapter = CICIDS2018Adapter("CIC", sample_csv)
    records = list(adapter.get_records())
    
    if not records:
        print("No valid records found in sample.")
    else:
        sample_record = records[0] # Benign row
        print(f"Loaded sample record: {sample_record.flow_id} (Actual Label: {sample_record.label.name})")
        
        engine = BaselineInferenceEngine("models/baseline", "RandomForest")
        result = engine.predict(sample_record)
        print("Inference Result:")
        print(json.dumps(result, indent=2))

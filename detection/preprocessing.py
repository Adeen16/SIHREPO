import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Optional
from dataset.schema import ExternalDatasetRecord
from detection.baseline_config import Phase8FeatureConfig
import os

class FeaturePreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False

    def extract_features(self, record: ExternalDatasetRecord) -> Optional[np.ndarray]:
        """
        Extracts the exact feature vector from an ExternalDatasetRecord in the order
        defined by Phase8FeatureConfig.
        Returns None if MISSING_VALUE_POLICY is 'reject' and any feature is missing.
        """
        vector = []
        for feature_name in Phase8FeatureConfig.FEATURES:
            val = getattr(record, feature_name, None)
            if val is None:
                if Phase8FeatureConfig.MISSING_VALUE_POLICY == "reject":
                    return None
                else:
                    vector.append(0.0) # Fallback imputation if we changed policy
            else:
                vector.append(float(val))
        return np.array(vector)

    def extract_dataset(self, records: List[ExternalDatasetRecord]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Extracts valid features and labels from a list of records.
        Returns X (features), y (labels as ints), and flow_ids.
        """
        X_list = []
        y_list = []
        ids_list = []

        for rec in records:
            vec = self.extract_features(rec)
            if vec is not None and rec.label.value >= 0: # Reject CanonicalLabel.UNKNOWN (-1) from training natively
                X_list.append(vec)
                y_list.append(rec.label.value)
                ids_list.append(rec.flow_id)

        return np.array(X_list), np.array(y_list), np.array(ids_list)

    def fit(self, X: np.ndarray):
        """Fits the StandardScaler on training data only."""
        self.scaler.fit(X)
        self.is_fitted = True

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transforms data using the fitted scaler."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform.")
        return self.scaler.transform(X)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self.scaler, filepath)

    def load(self, filepath: str):
        self.scaler = joblib.load(filepath)
        self.is_fitted = True

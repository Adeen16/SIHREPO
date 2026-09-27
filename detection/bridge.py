import numpy as np
from typing import Dict
from detection.baseline_config import Phase8FeatureConfig

class Phase6toPhase8Bridge:
    """
    Explicitly converts the 16-feature Phase 6 canonical representation
    into the 13-feature Phase 8 offline ML baseline vector.

    The Phase 8 baseline deliberately omits three contextual features:
    - src_ip_flow_count
    - src_ip_unique_dst_ips
    - src_ip_unique_dst_ports

    These are excluded because the offline CIC-IDS2018 dataset used for training
    cannot provide them. They are NEVER fabricated here.
    """

    def __init__(self):
        self.expected_features = Phase8FeatureConfig.FEATURES

    def convert(self, phase6_features: Dict[str, float]) -> np.ndarray:
        """
        Validates and converts a Phase 6 feature dictionary into a 13-element numpy array.
        """
        vector = []
        for feature_name in self.expected_features:
            if feature_name not in phase6_features:
                raise ValueError(f"Required Phase 8 feature missing from Phase 6 output: {feature_name}")

            val = phase6_features[feature_name]
            if val is None:
                raise ValueError(f"Phase 6 feature '{feature_name}' cannot be None.")

            vector.append(float(val))

        return np.array(vector)

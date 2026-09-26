from typing import List, Dict, Any
import json
import os

class Phase8FeatureConfig:
    """
    Explicit Phase 8 Feature Contract.
    Defines exactly which features are extracted, their order, and missing-value policies.
    """
    
    # We select CIC-IDS2018 subset of Phase 6 features, because it provides 13/16 features.
    # We do NOT include src_ip_flow_count etc. since they are structurally missing in CIC CSV.
    FEATURES: List[str] = [
        "flow_duration",
        "fwd_packet_count",
        "rev_packet_count",
        "fwd_byte_count",
        "rev_byte_count",
        "fwd_bytes_per_sec",
        "rev_bytes_per_sec",
        "fwd_pkts_per_sec",
        "rev_pkts_per_sec",
        "byte_ratio",
        "is_unidirectional",
        "is_tcp",
        "is_udp"
    ]
    
    INPUT_DIMENSION = len(FEATURES)
    
    # Missing Value Policy: 'reject' or 'impute'. 
    # For baseline on CIC, these 13 features should be natively present.
    # Records with None for these fields are rejected from training to prevent fabrication.
    MISSING_VALUE_POLICY = "reject"
    
    @classmethod
    def save(cls, filepath: str):
        config_data = {
            "features": cls.FEATURES,
            "input_dimension": cls.INPUT_DIMENSION,
            "missing_value_policy": cls.MISSING_VALUE_POLICY
        }
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=4)
            
    @classmethod
    def load(cls, filepath: str) -> Dict[str, Any]:
        with open(filepath, 'r') as f:
            return json.load(f)

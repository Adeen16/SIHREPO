from processing.window import WindowSnapshot
from typing import Dict

class CICCompatFeatureExtractor:
    """
    Extracts features compatible with CICFlowMeter to allow models trained on CSVs
    to be served from real PCAPs.
    """
    def extract_features(self, snapshot: WindowSnapshot) -> Dict[str, Dict[str, float]]:
        features = {}
        for flow_id, flow_state in snapshot.flows.items():
            features[flow_id] = {
                "flow_duration_us": float(flow_state.end_time - flow_state.start_time) * 1e6 if flow_state.start_time else 0.0,
                "fwd_packets": float(flow_state.fwd_packets),
                "bwd_packets": float(flow_state.rev_packets),
                "fwd_bytes": float(flow_state.fwd_bytes),
                "bwd_bytes": float(flow_state.rev_bytes),
                # other basic stats mapped
            }
        return features

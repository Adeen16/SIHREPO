from detection.detectors.base import BaseDetector, DetectionResult

class ExfiltrationDetector(BaseDetector):
    """
    Detects Data Exfiltration using asymmetric byte ratios and volume.
    Currently UNVALIDATED due to lack of explicit exfiltration PCAP.
    """
    def __init__(self, min_bytes: int = 1_000_000, outbound_ratio_threshold: float = 0.95):
        self.min_bytes = min_bytes
        self.outbound_ratio_threshold = outbound_ratio_threshold

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        
        fwd_bytes = phase6_features.get("fwd_byte_count", 0)
        rev_bytes = phase6_features.get("rev_byte_count", 0)
        total_bytes = fwd_bytes + rev_bytes
        
        if total_bytes < self.min_bytes:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="NOT_DETECTED",
                detector_name=self.name
            )
            
        byte_ratio = phase6_features.get("byte_ratio", 0.0)
        
        # If byte_ratio > 0.95, 95% of traffic is outbound (assuming fwd is outbound)
        if byte_ratio >= self.outbound_ratio_threshold:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="UNVALIDATED",  # As required by PS145 missing data policy
                threat_type="DATA_EXFILTRATION",
                severity="HIGH",
                score=byte_ratio,
                detector_name=self.name,
                evidence={
                    "total_bytes": total_bytes,
                    "byte_ratio": byte_ratio,
                    "reason": "massive asymmetric outbound transfer",
                    "note": "Detector unvalidated without real exfiltration dataset."
                }
            )
            
        return DetectionResult(
            flow_id=flow_id,
            timestamp=window_snapshot.window_end,
            status="NOT_DETECTED",
            detector_name=self.name
        )

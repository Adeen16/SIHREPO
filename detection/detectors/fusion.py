from typing import List, Dict, Any
from detection.detectors.base import DetectionResult

class FusionEngine:
    """
    Fuses multiple DetectionResults for a single flow into one unified result.
    Enforces a strict severity priority to resolve contradictory detections.
    """

    # Priority rank: higher index = higher priority
    SEVERITY_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def fuse(self, flow_id: str, timestamp: float, results: List[DetectionResult]) -> DetectionResult:
        """
        Takes a list of raw DetectionResults from individual detectors and returns a single fused result.
        """
        valid_detections = [r for r in results if r.status == "DETECTED"]
        unvalidated_detections = [r for r in results if r.status == "UNVALIDATED"]
        errors = [r for r in results if r.status == "error"]

        # If any detector threw an error during evaluation, surface it
        if errors:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="error",
                error_message="; ".join(str(e.evidence.get("error")) for e in errors if e.evidence and "error" in e.evidence)
            )

        if not valid_detections:
            # If nothing was detected but an unvalidated detector flagged it, emit the unvalidated result.
            if unvalidated_detections:
                return self._select_highest_priority(unvalidated_detections)

            # Otherwise, BENIGN
            return DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="BENIGN",
                threat_type="BENIGN",
                confidence=1.0,
                detector_name="FusionEngine",
                evidence={"reason": "No threat signatures detected"}
            )

        # Select the highest severity valid detection
        return self._select_highest_priority(valid_detections)

    # Priority rank for threat classes to resolve genuine ties.
    # Higher value = higher priority in a tie-break.
    # DDoS/Exfiltration are most severe (immediate impact), Recon next, then C2, then ambiguous anomalies.
    THREAT_CLASS_PRIORITY = {
        "DDoS": 100,
        "DATA_EXFILTRATION": 90,
        "RECONNAISSANCE": 80,
        "C2_BEACONING": 70,
        "DNS_DGA_TUNNEL": 60,
        "ENCRYPTED_MALWARE": 50
    }

    def _select_highest_priority(self, detections: List[DetectionResult]) -> DetectionResult:
        highest_det = detections[0]
        highest_rank = self.SEVERITY_RANK.get(highest_det.severity, 0)
        
        for det in detections[1:]:
            rank = self.SEVERITY_RANK.get(det.severity, 0)
            
            if rank > highest_rank:
                highest_det = det
                highest_rank = rank
            elif rank == highest_rank:
                score1 = highest_det.confidence or highest_det.score or 0.0
                score2 = det.confidence or det.score or 0.0
                
                # Check for a genuine tie within a small epsilon (0.02)
                if abs(score2 - score1) <= 0.02:
                    # Break tie using explicit documented threat class priority
                    prio1 = self.THREAT_CLASS_PRIORITY.get(highest_det.threat_type, 0)
                    prio2 = self.THREAT_CLASS_PRIORITY.get(det.threat_type, 0)
                    if prio2 > prio1:
                        highest_det = det
                elif score2 > score1:
                    highest_det = det

        return highest_det

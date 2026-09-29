from typing import List, Dict, Any, Tuple
from detection.detectors.base import DetectionResult


class FusionEngine:
    """
    Fuses multiple DetectionResults for a single flow into one unified result.
    Enforces a strict severity priority to resolve contradictory detections.
    Also attaches all_detector_results and a human-readable fusion_reason.
    """

    # Priority rank: higher index = higher priority
    SEVERITY_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    # Priority rank for threat classes to resolve genuine ties.
    THREAT_CLASS_PRIORITY = {
        "DDoS": 100,
        "DATA_EXFILTRATION": 90,
        "RECONNAISSANCE": 80,
        "C2_BEACONING": 70,
        "DNS_DGA_TUNNEL": 60,
        "ENCRYPTED_MALWARE": 50
    }

    def fuse(self, flow_id: str, timestamp: float, results: List[DetectionResult]) -> DetectionResult:
        """
        Takes a list of raw DetectionResults from individual detectors and returns a single fused result.
        Attaches all_detector_results (per-detector snapshot) and fusion_reason to the winner.
        """
        # Snapshot ALL detector outputs for the evidence panel, before fusion resolves the winner
        all_detector_snapshot = [
            {
                "detector": r.detector_name or "unknown",
                "status": r.status,
                "threat_type": r.threat_type,
                "confidence": r.confidence,
                "evidence": r.evidence or {},
            }
            for r in results
        ]

        valid_detections = [r for r in results if r.status == "DETECTED"]
        unvalidated_detections = [r for r in results if r.status == "UNVALIDATED"]
        errors = [r for r in results if r.status == "error"]

        # If any detector threw an error during evaluation, surface it
        if errors:
            winner = DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="error",
                error_message="; ".join(str(e.evidence.get("error")) for e in errors if e.evidence and "error" in e.evidence)
            )
            winner.all_detector_results = all_detector_snapshot
            winner.fusion_reason = f"{len(errors)} detector(s) raised exceptions"
            return winner

        if not valid_detections:
            if unvalidated_detections:
                winner = self._select_highest_priority(unvalidated_detections)
                fired = [r.detector_name for r in unvalidated_detections]
                winner.all_detector_results = all_detector_snapshot
                winner.fusion_reason = f"Unvalidated signal from: {', '.join(f for f in fired if f)}"
                return winner

            winner = DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="BENIGN",
                threat_type="BENIGN",
                confidence=1.0,
                detector_name="FusionEngine",
                evidence={"reason": "No threat signatures detected"}
            )
            winner.all_detector_results = all_detector_snapshot
            winner.fusion_reason = "No detector fired"
            return winner

        # Select the highest severity valid detection and get the reason
        winner, reason = self._select_highest_priority_with_reason(valid_detections)
        winner.all_detector_results = all_detector_snapshot
        winner.fusion_reason = reason
        return winner

    def _select_highest_priority(self, detections: List[DetectionResult]) -> DetectionResult:
        winner, _ = self._select_highest_priority_with_reason(detections)
        return winner

    def _select_highest_priority_with_reason(self, detections: List[DetectionResult]) -> Tuple[DetectionResult, str]:
        highest_det = detections[0]
        highest_rank = self.SEVERITY_RANK.get(highest_det.severity, 0)
        reason = "only detector to fire" if len(detections) == 1 else "highest severity"

        for det in detections[1:]:
            rank = self.SEVERITY_RANK.get(det.severity, 0)

            if rank > highest_rank:
                old_sev = highest_det.severity
                highest_det = det
                highest_rank = rank
                reason = f"higher severity {det.severity} vs {old_sev}"
            elif rank == highest_rank:
                score1 = highest_det.confidence or highest_det.score or 0.0
                score2 = det.confidence or det.score or 0.0

                # Check for a genuine tie within a small epsilon (0.02)
                if abs(score2 - score1) <= 0.02:
                    # Break tie using explicit documented threat class priority
                    prio1 = self.THREAT_CLASS_PRIORITY.get(highest_det.threat_type, 0)
                    prio2 = self.THREAT_CLASS_PRIORITY.get(det.threat_type, 0)
                    if prio2 > prio1:
                        old_type = highest_det.threat_type
                        highest_det = det
                        reason = f"threat class priority {det.threat_type} > {old_type} (confidence tied)"
                elif score2 > score1:
                    old_score = score1
                    highest_det = det
                    reason = f"higher confidence {score2:.2f} vs {old_score:.2f}"

        if len(detections) == 1:
            reason = "only detector to fire"

        return highest_det, reason

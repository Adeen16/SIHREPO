import math
from typing import Dict, Any
from detection.detectors.base import BaseDetector, DetectionResult

class C2BeaconingDetector(BaseDetector):
    """
    Detects Botnet C2 Beaconing using inter-arrival time (IAT) regularity,
    accumulated across multiple observation windows to avoid missing slow beacons.
    """
    def __init__(self, min_packets: int = 4, max_cv: float = 0.1, min_duration: float = 2.0, max_history_age: float = 300.0):
        self.min_packets = min_packets
        # Coefficient of Variation (stddev / mean). A low CV means highly regular timing.
        # 0.1 represents 10% standard deviation relative to mean, which is highly periodic.
        self.max_cv = max_cv
        self.min_duration = min_duration
        self.max_history_age = max_history_age


        # State tracking across windows
        # format: { flow_id: { "total_packets": int, "iat_count": int, "iat_mean": float, "iat_m2": float, "last_seen": float, "first_seen": float } }
        self.flow_history: Dict[str, Dict[str, Any]] = {}
        self.last_purge: float = 0.0

    def _purge_old_history(self, current_time: float):
        if current_time - self.last_purge < 10.0:
            return
        self.last_purge = current_time
        keys_to_delete = []
        for fid, state in self.flow_history.items():
            if current_time - state["last_seen"] > self.max_history_age:
                keys_to_delete.append(fid)
        for k in keys_to_delete:
            del self.flow_history[k]

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        current_time = window_snapshot.window_end

        self._purge_old_history(current_time)

        # Initialize or update state
        if flow_id not in self.flow_history:
            self.flow_history[flow_id] = {
                "total_packets": 0,
                "iat_count": 0,
                "iat_mean": 0.0,
                "iat_m2": 0.0,
                "first_seen": flow_state.first_seen,
                "last_seen": flow_state.last_seen,
                "dst_ip": flow_state.dst_ip
            }

        history = self.flow_history[flow_id]

        # Since flow_state is rebuilt per window, we must merge its IAT stats with history.
        # However, it's safer to just accumulate packets directly if we could,
        # but since we only get the flow_state for the window, we add the new window's packets to history.
        # Wait, if windows overlap, we will double count!
        # Instead, we just trust flow_state if it represents a longer sliding window.
        # But wait, if window_snapshot is strictly the packets in this window, we can't just sum them blindly due to sliding overlap.
        # But the problem explicitly states: "bounded temporal observation mechanism that allows beacon detection across multiple consecutive windows."
        # A simpler way: just record the timestamp of the flow in THIS window.

        # We can record the time of each window where the flow is active.
        if "active_windows" not in history:
            history["active_windows"] = []

        if current_time not in history["active_windows"]:
            history["active_windows"].append(current_time)

        history["last_seen"] = current_time

        # Keep only windows within the last max_history_age
        history["active_windows"] = [t for t in history["active_windows"] if current_time - t <= self.max_history_age]

        # We also need to evaluate the CURRENT flow_state's IAT if it has enough packets
        cv = None
        if flow_state._iat_count >= 2 and flow_state._iat_mean > 0.0:
            variance = flow_state._iat_m2 / (flow_state._iat_count - 1)
            stddev = math.sqrt(variance)
            cv = stddev / flow_state._iat_mean

        # 1. Exclusion of Infrastructure Traffic
        INFRA_PORTS = {53, 67, 68, 123, 137, 138, 161, 162, 389, 636, 5353}
        INFRA_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}
        if flow_state.dst_port in INFRA_PORTS or flow_state.src_port in INFRA_PORTS:
            return DetectionResult(flow_id=flow_id, timestamp=current_time, status="NOT_DETECTED", detector_name=self.name)
        if history["dst_ip"] in INFRA_IPS or flow_state.src_ip in INFRA_IPS:
            return DetectionResult(flow_id=flow_id, timestamp=current_time, status="NOT_DETECTED", detector_name=self.name)

        windows_seen = len(history["active_windows"])
        
        # Calculate timespan
        observation_span = 0.0
        if windows_seen > 0:
            observation_span = history["active_windows"][-1] - history["active_windows"][0]

        # C2 beacons are typically small control packets
        avg_packet_size = flow_state.byte_count / flow_state.packet_count if flow_state.packet_count > 0 else 0
        is_small_packets = avg_packet_size < 300

        # Must meet hard minimums
        MIN_WINDOWS = 10
        MIN_SPAN = 60.0
        
        if cv is None or cv > self.max_cv or windows_seen < MIN_WINDOWS or observation_span < MIN_SPAN or not is_small_packets or flow_state.packet_count < self.min_packets:
            return DetectionResult(flow_id=flow_id, timestamp=current_time, status="NOT_DETECTED", detector_name=self.name)

        # 2. Continuous Scoring
        # a) Regularity score: 1.0 if CV is 0, approaches 0 as CV approaches max_cv
        regularity_score = 1.0 - (cv / self.max_cv)
        
        # b) Sustained span score: scales from 0.0 to 1.0 as it exceeds minimums
        # Scale up to 30 windows for max score
        sustained_score = min(1.0, (windows_seen - MIN_WINDOWS) / 20.0)
        
        # c) Volume score: scales based on packets
        volume_score = min(1.0, (flow_state.packet_count - self.min_packets) / 50.0)

        # Weighted combination
        confidence = (0.5 * regularity_score) + (0.35 * sustained_score) + (0.15 * volume_score)

        # Require a minimum confidence floor
        if confidence < 0.75:
            return DetectionResult(flow_id=flow_id, timestamp=current_time, status="NOT_DETECTED", detector_name=self.name)

        reasons = [
            f"Highly regular timing (CV={cv:.3f})",
            f"Sustained over {windows_seen} windows ({observation_span:.1f}s)",
            f"Non-infrastructure port ({flow_state.dst_port})"
        ]

        return DetectionResult(
            flow_id=flow_id,
            timestamp=current_time,
            status="DETECTED",
            threat_type="C2_BEACONING",
            severity="HIGH",
            confidence=confidence,
            detector_name=self.name,
            evidence={
                "periodicity_cv": cv,
                "windows_seen": windows_seen,
                "observation_span": observation_span,
                "packet_count": flow_state.packet_count,
                "dst_ip": history["dst_ip"],
                "dst_port": flow_state.dst_port,
                "reason": " and ".join(reasons)
            }
        )

        return DetectionResult(
            flow_id=flow_id,
            timestamp=current_time,
            status="NOT_DETECTED",
            detector_name=self.name
        )

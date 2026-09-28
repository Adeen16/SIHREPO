import math
from typing import Dict, Any
from detection.detectors.base import BaseDetector, DetectionResult

class C2BeaconingDetector(BaseDetector):
    """
    Detects Botnet C2 Beaconing using inter-arrival time (IAT) regularity,
    accumulated across multiple observation windows to avoid missing slow beacons.
    """
    def __init__(self, min_packets: int = 4, max_cv: float = 1.5, min_duration: float = 2.0, max_history_age: float = 300.0):
        self.min_packets = min_packets
        # Coefficient of Variation (stddev / mean). A low CV means highly regular timing.
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

        windows_seen = len(history["active_windows"])

        # C2 beacons are typically small control packets sent to well-known ports (80, 443, 53)
        avg_packet_size = flow_state.byte_count / flow_state.packet_count if flow_state.packet_count > 0 else 0
        is_small_packets = avg_packet_size < 300

        # P2P DHT (UDP) often mimics beacons due to regular pings to high ports.
        is_service_port = flow_state.dst_port <= 10000

        signals = 0
        reasons = []

        # 1. High regularity in the current window
        if cv is not None and cv <= self.max_cv:
            signals += 1
            reasons.append(f"Highly regular inter-arrival timing (CV={cv:.2f})")

        # 2. Repeated communication across many windows (Sustained periodic communication)
        if windows_seen >= 5:
            signals += 1
            reasons.append(f"Sustained communication across {windows_seen} windows")

        # 3. Sufficient packets
        if flow_state.packet_count >= self.min_packets:
            signals += 1
            reasons.append(f"Sufficient packet volume ({flow_state.packet_count})")

        if signals >= 2 and windows_seen >= 3 and is_small_packets and is_service_port:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=current_time,
                status="DETECTED",
                threat_type="C2_BEACONING",
                severity="HIGH",
                confidence=min(1.0, signals / 3.0),
                detector_name=self.name,
                evidence={
                    "periodicity_cv": cv,
                    "windows_seen": windows_seen,
                    "packet_count": flow_state.packet_count,
                    "dst_ip": history["dst_ip"],
                    "reason": " and ".join(reasons)
                }
            )

        return DetectionResult(
            flow_id=flow_id,
            timestamp=current_time,
            status="NOT_DETECTED",
            detector_name=self.name
        )

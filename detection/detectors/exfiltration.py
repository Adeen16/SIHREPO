from typing import Dict, Any
from detection.detectors.base import BaseDetector, DetectionResult

class ExfiltrationDetector(BaseDetector):
    """
    Detects Data Exfiltration based on sustained asymmetric outbound transfer behavior.
    Monitors flow ratio (outbound vs inbound bytes) over a period of time.
    """
    def __init__(self, min_bytes: int = 1000000, min_ratio: float = 10.0, max_history_age: float = 300.0):
        self.min_bytes = min_bytes  # Minimum total outbound bytes to trigger (e.g. 1MB)
        self.min_ratio = min_ratio  # Minimum outbound/inbound ratio
        self.max_history_age = max_history_age

        # State tracking by src_ip -> dst_ip
        # format: { "src->dst": { "fwd_bytes": int, "rev_bytes": int, "last_seen": float, "windows_seen": int } }
        self.history: Dict[str, Dict[str, Any]] = {}
        self.last_purge: float = 0.0

    def _purge_old_history(self, current_time: float):
        if current_time - self.last_purge < 10.0:
            return
        self.last_purge = current_time
        keys_to_delete = []
        for k, state in self.history.items():
            if current_time - state["last_seen"] > self.max_history_age:
                keys_to_delete.append(k)
        for k in keys_to_delete:
            del self.history[k]

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        current_time = window_snapshot.window_end

        self._purge_old_history(current_time)

        # For exfiltration, we care about the initiator (src) sending data to (dst)
        host_key = f"{flow_state.src_ip}->{flow_state.dst_ip}"

        if host_key not in self.history:
            self.history[host_key] = {
                "fwd_bytes": 0,
                "rev_bytes": 0,
                "last_seen": current_time,
                "windows_seen": 0
            }

        state = self.history[host_key]
        state["last_seen"] = current_time
        state["windows_seen"] += 1

        # We accumulate the MAX byte count seen for any flow between this src and dst
        # because flow_state byte counts are cumulative over the flow's lifetime
        state["fwd_bytes"] = max(state["fwd_bytes"], flow_state.fwd_byte_count)
        state["rev_bytes"] = max(state["rev_bytes"], flow_state.rev_byte_count)

        fwd = state["fwd_bytes"]
        rev = state["rev_bytes"]

        # Exfiltration is strictly internal -> external
        is_internal_src = flow_state.src_ip.startswith("10.") or flow_state.src_ip.startswith("192.168.") or flow_state.src_ip.startswith("172.")
        is_internal_dst = flow_state.dst_ip.startswith("10.") or flow_state.dst_ip.startswith("192.168.") or flow_state.dst_ip.startswith("172.")

        if not is_internal_src or is_internal_dst:
            # Not an internal host sending to the internet
            return DetectionResult(flow_id=flow_id, timestamp=current_time, status="NOT_DETECTED", detector_name=self.name)

        # To avoid division by zero
        safe_rev = rev if rev > 0 else 1
        ratio = fwd / safe_rev

        signals = 0
        reasons = []

        if fwd >= self.min_bytes:
            signals += 1
            reasons.append(f"High outbound volume ({fwd} bytes)")

        if ratio >= self.min_ratio:
            signals += 1
            reasons.append(f"Highly asymmetric transfer (Out/In ratio: {ratio:.1f})")

        if state["windows_seen"] >= 2:
            signals += 1
            reasons.append(f"Sustained transfer ({state['windows_seen']} windows)")

        # Must meet all core criteria
        if signals >= 3:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=current_time,
                status="DETECTED",
                threat_type="DATA_EXFILTRATION",
                severity="HIGH",
                confidence=min(1.0, (fwd / self.min_bytes) * 0.5 + 0.5),
                detector_name=self.name,
                evidence={
                    "outbound_bytes": fwd,
                    "inbound_bytes": rev,
                    "outbound_inbound_ratio": ratio,
                    "windows_active": state["windows_seen"],
                    "reason": " and ".join(reasons)
                }
            )

        return DetectionResult(
            flow_id=flow_id,
            timestamp=current_time,
            status="NOT_DETECTED",
            detector_name=self.name
        )

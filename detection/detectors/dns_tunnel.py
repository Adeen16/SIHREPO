import math
from typing import Dict, Any, List
from detection.detectors.base import BaseDetector, DetectionResult

class DNSTunnelDetector(BaseDetector):
    """
    Detects DGA / DNS Tunnelling using a hybrid stateful approach.
    Monitors queries per IP pair across multiple windows to handle source port randomization.
    """
    def __init__(self, min_entropy: float = 4.0, min_queries: int = 15, max_history_age: float = 120.0):
        self.min_entropy = min_entropy
        self.min_queries = min_queries
        self.max_history_age = max_history_age

        # State tracking by src_ip -> dst_ip
        # format: { "src->dst": { "last_seen": float, "queries": [] } }
        self.history: Dict[str, Dict[str, Any]] = {}
        self.last_purge: float = 0.0

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freqs = {}
        for char in data:
            freqs[char] = freqs.get(char, 0) + 1
        for freq in freqs.values():
            p = freq / length
            entropy -= p * math.log2(p)
        return entropy

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

        # Only evaluate UDP Port 53 flows
        if flow_state.protocol != 'UDP' or (flow_state.src_port != 53 and flow_state.dst_port != 53):
            return DetectionResult(
                flow_id=flow_id,
                timestamp=current_time,
                status="NOT_DETECTED",
                detector_name=self.name
            )

        self._purge_old_history(current_time)

        host_key = f"{flow_state.src_ip}->{flow_state.dst_ip}"
        if host_key not in self.history:
            self.history[host_key] = {"last_seen": current_time, "queries": set()}

        history_state = self.history[host_key]
        history_state["last_seen"] = current_time

        queries = flow_state.metadata.get("dns_queries", [])
        for q in queries:
            history_state["queries"].add(q.get("name", ""))

        unique_queries = list(history_state["queries"])

        if len(unique_queries) < self.min_queries:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=current_time,
                status="INSUFFICIENT_DATA",
                detector_name=self.name
            )

        high_entropy_count = 0
        total_entropy = 0.0
        total_len = 0

        for name in unique_queries:
            ent = self._shannon_entropy(name)
            total_entropy += ent
            total_len += len(name)
            if ent > self.min_entropy:
                high_entropy_count += 1

        avg_entropy = total_entropy / len(unique_queries)
        avg_len = total_len / len(unique_queries)

        signals = 0
        reasons = []

        if avg_entropy >= self.min_entropy:
            signals += 1
            reasons.append(f"High average domain entropy ({avg_entropy:.2f})")

        if (high_entropy_count / len(unique_queries)) >= 0.5:
            signals += 1
            reasons.append(f"High ratio of high-entropy domains ({high_entropy_count}/{len(unique_queries)})")

        if avg_len >= 20.0:
            signals += 1
            reasons.append(f"Abnormal average domain length ({avg_len:.1f} chars)")

        if signals >= 2:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=current_time,
                status="DETECTED",
                threat_type="DNS_DGA_TUNNEL",
                severity="HIGH",
                score=min(1.0, signals / 3.0),
                detector_name=self.name,
                evidence={
                    "unique_queries_across_windows": len(unique_queries),
                    "domain_entropy_avg": avg_entropy,
                    "domain_length_avg": avg_len,
                    "high_entropy_queries": high_entropy_count,
                    "reason": " and ".join(reasons)
                }
            )

        return DetectionResult(
            flow_id=flow_id,
            timestamp=current_time,
            status="NOT_DETECTED",
            detector_name=self.name
        )

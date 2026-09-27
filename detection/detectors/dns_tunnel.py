import math
from detection.detectors.base import BaseDetector, DetectionResult

class DNSTunnelDetector(BaseDetector):
    """
    Detects DGA / DNS Tunnelling based on domain entropy and high DNS query rates.
    """
    def __init__(self, min_entropy: float = 4.5, min_queries: int = 15):
        self.min_entropy = min_entropy
        self.min_queries = min_queries

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

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        
        # Only evaluate UDP Port 53 flows
        if flow_state.protocol != 'UDP' or (flow_state.src_port != 53 and flow_state.dst_port != 53):
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="NOT_DETECTED",
                detector_name=self.name
            )
            
        queries = flow_state.metadata.get("dns_queries", [])
        if len(queries) < self.min_queries:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="INSUFFICIENT_DATA",
                detector_name=self.name
            )
            
        high_entropy_count = 0
        total_entropy = 0.0
        total_len = 0
        
        for q in queries:
            name = q.get("name", "")
            ent = self._shannon_entropy(name)
            total_entropy += ent
            total_len += len(name)
            if ent > self.min_entropy:
                high_entropy_count += 1
                
        avg_entropy = total_entropy / len(queries)
        avg_len = total_len / len(queries)
        
        # If average entropy is high or a significant portion is high entropy
        if avg_entropy >= self.min_entropy or (high_entropy_count / len(queries)) >= 0.5:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="DETECTED",
                threat_type="DNS_DGA_TUNNEL",
                severity="HIGH",
                score=min(1.0, avg_entropy / 6.0),  # Normalize roughly
                detector_name=self.name,
                evidence={
                    "queries_per_window": len(queries),
                    "domain_entropy_avg": avg_entropy,
                    "domain_length_avg": avg_len,
                    "high_entropy_queries": high_entropy_count,
                    "reason": "high-entropy high-frequency DNS activity"
                }
            )
            
        return DetectionResult(
            flow_id=flow_id,
            timestamp=window_snapshot.window_end,
            status="NOT_DETECTED",
            detector_name=self.name
        )

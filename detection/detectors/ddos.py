from typing import Dict, Any
from detection.detectors.base import BaseDetector, DetectionResult
from detection.bridge import Phase6toPhase8Bridge
from detection.inference import BaselineInferenceEngine

class DDoSDetector(BaseDetector):
    """
    Detects Volumetric DDoS using a hybrid approach:
    Combines the Phase 8 Random Forest ML baseline with deterministic volumetric evidence.
    """
    def __init__(self, model_dir: str, model_name: str = "RandomForest"):
        self.bridge = Phase6toPhase8Bridge()
        self.inference_engine = BaselineInferenceEngine(model_dir=model_dir, model_name=model_name)

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id

        try:
            # Volumetric calculations
            fwd_pps = phase6_features.get("fwd_pkts_per_sec", 0)
            rev_pps = phase6_features.get("rev_pkts_per_sec", 0)
            total_pps = fwd_pps + rev_pps

            fwd_bps = phase6_features.get("fwd_bytes_per_sec", 0)
            rev_bps = phase6_features.get("rev_bytes_per_sec", 0)
            total_bps = fwd_bps + rev_bps

            # Flow concentration to destination IP in this window
            # Cache this per window to avoid O(N^2) complexity on large windows
            if not hasattr(self, "_last_window_end") or self._last_window_end != window_snapshot.window_end:
                self._last_window_end = window_snapshot.window_end
                self._dst_stats = {}

            dst_ip = flow_state.dst_ip
            if dst_ip not in self._dst_stats:
                f_to_dst = 0
                p_to_dst = 0
                u_src_ips = set()
                for active_flow in window_snapshot.flows.values():
                    if active_flow.dst_ip == dst_ip:
                        f_to_dst += 1
                        p_to_dst += active_flow.packet_count
                        u_src_ips.add(active_flow.src_ip)
                self._dst_stats[dst_ip] = {
                    "flows_to_dst": f_to_dst,
                    "packets_to_dst": p_to_dst,
                    "unique_src_count": len(u_src_ips),
                    "ml_predicted": None
                }

            dst_info = self._dst_stats[dst_ip]
            flows_to_dst = dst_info["flows_to_dst"]
            packets_to_dst = dst_info["packets_to_dst"]
            unique_src_count = dst_info["unique_src_count"]

            # P2P exclusion: DDoS typically targets well-known server ports.
            # BitTorrent or other P2P apps often use ephemeral high ports (> 10000).
            is_service_port = flow_state.dst_port <= 10000

            # Heuristic thresholds
            # 1. Flow concentration (e.g., SYN flood creates many distinct flows to the same IP)
            is_concentrated = (flows_to_dst > 50 or unique_src_count > 20) and is_service_port

            # 2. Burst traffic from MULTIPLE flows
            # If all packets are from 1 flow, it's a file download/video.
            is_burst = (packets_to_dst > 2000) and (flows_to_dst > 5) and is_service_port

            # 3. High overall packet rate
            is_high_volume = total_pps > 1000

            # Hybrid Fusion:
            signals = 0
            reasons = []

            if is_high_volume:
                signals += 1
                reasons.append(f"High traffic volume ({total_pps:.2f} pkts/sec)")
            if is_concentrated:
                signals += 2 # Strong signal
                reasons.append(f"High flow concentration ({flows_to_dst} flows, {unique_src_count} src IPs to {flow_state.dst_ip})")
            if is_burst:
                signals += 2 # Strong signal
                reasons.append(f"Distributed burst traffic ({packets_to_dst} total packets to {flow_state.dst_ip})")

            # Only run ML inference if we have enough volumetric signals to potentially trigger an alert (needs >=2 before ML, since ML gives +1)
            is_ml_ddos = False
            if signals >= 2:
                if dst_info["ml_predicted"] is None:
                    vector = self.bridge.convert(phase6_features)
                    inference_output = self.inference_engine.predict(vector)
                    predicted_class = inference_output.get("predicted_class", "")
                    dst_info["ml_predicted"] = bool(predicted_class in ["DDOS", "1", 1] or (isinstance(predicted_class, str) and "DDOS" in predicted_class.upper()))
                
                is_ml_ddos = dst_info["ml_predicted"]
                if is_ml_ddos:
                    signals += 1
                    reasons.append("ML model predicted DDoS")

            # Must have at least 3 points of evidence to alert (e.g. concentrated + ML, or concentrated + burst)
            if signals >= 3:
                return DetectionResult(
                    flow_id=flow_id,
                    timestamp=window_snapshot.window_end,
                    status="DETECTED",
                    threat_type="DDoS",
                    severity="HIGH",
                    confidence=min(1.0, signals / 3.0),
                    detector_name=self.name,
                    evidence={
                        "packets_per_sec": total_pps,
                        "bytes_per_sec": total_bps,
                        "flows_to_dst": flows_to_dst,
                        "reason": " and ".join(reasons)
                    }
                )
            else:
                return DetectionResult(
                    flow_id=flow_id,
                    timestamp=window_snapshot.window_end,
                    status="NOT_DETECTED",
                    detector_name=self.name
                )

        except Exception as e:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="error",
                detector_name=self.name,
                error_message=str(e),
                evidence={"error": str(e)}
            )

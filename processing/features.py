from typing import Dict, Any
from processing.window import WindowSnapshot
from processing.feature_math import compute_byte_ratio

class FeatureExtractor:
    """
    Extracts numerical features from a WindowSnapshot for ML inference.
    Produces flow-level feature vectors enriched with window-context aggregations.
    """
    
    def extract_features(self, snapshot: WindowSnapshot) -> Dict[str, Dict[str, float]]:
        """
        Extracts features for all flows in the given WindowSnapshot.
        Returns a dictionary mapping flow_id to a feature dictionary.
        """
        features = {}
        
        # 1. Pre-compute window-context statistics (e.g., for Port Scan / DDoS detection)
        src_ip_stats = self._compute_src_ip_stats(snapshot)
        
        # 2. Compute flow-specific features
        for flow_id, flow in snapshot.flows.items():
            # duration: use actual value; rates are 0.0 at zero duration (documented)
            duration = flow.duration
            
            fwd_bytes = flow.fwd_byte_count
            rev_bytes = flow.rev_byte_count
            fwd_pkts = flow.fwd_packet_count
            rev_pkts = flow.rev_packet_count
            
            # Flow-level behavior
            # Rates are 0.0 when duration==0 (instantaneous flow); documented edge case.
            if duration > 0:
                fwd_bytes_per_sec = fwd_bytes / duration
                rev_bytes_per_sec = rev_bytes / duration
                fwd_pkts_per_sec = fwd_pkts / duration
                rev_pkts_per_sec = rev_pkts / duration
            else:
                fwd_bytes_per_sec = 0.0
                rev_bytes_per_sec = 0.0
                fwd_pkts_per_sec = 0.0
                rev_pkts_per_sec = 0.0

            flow_features = {
                "flow_duration": float(flow.duration),
                "fwd_packet_count": float(fwd_pkts),
                "rev_packet_count": float(rev_pkts),
                "fwd_byte_count": float(fwd_bytes),
                "rev_byte_count": float(rev_bytes),
                "fwd_bytes_per_sec": fwd_bytes_per_sec,
                "rev_bytes_per_sec": rev_bytes_per_sec,
                "fwd_pkts_per_sec": fwd_pkts_per_sec,
                "rev_pkts_per_sec": rev_pkts_per_sec,
                # byte_ratio uses shared compute_byte_ratio (processing/feature_math.py):
                # rev>0 -> fwd/rev; rev==0,fwd>0 -> BYTE_RATIO_CAP; both 0 -> 0.0
                "byte_ratio": compute_byte_ratio(fwd_bytes, rev_bytes),
            }
            
            # Enrich with source-IP context (essential for scanning/flooding detection)
            src_ip = flow.src_ip
            context = src_ip_stats.get(src_ip, {})
            flow_features["src_ip_flow_count"] = float(context.get("flow_count", 1))
            flow_features["src_ip_unique_dst_ips"] = float(len(context.get("unique_dst_ips", set())))
            flow_features["src_ip_unique_dst_ports"] = float(len(context.get("unique_dst_ports", set())))
            
            # Additional context (e.g., protocol encoding)
            flow_features["is_tcp"] = 1.0 if flow.protocol == "TCP" else 0.0
            flow_features["is_udp"] = 1.0 if flow.protocol == "UDP" else 0.0
            
            features[flow_id] = flow_features
            
        return features

    def _compute_src_ip_stats(self, snapshot: WindowSnapshot) -> Dict[str, Dict[str, Any]]:
        """
        Computes aggregate statistics for each source IP across the entire window.
        """
        stats = {}
        for flow in snapshot.flows.values():
            src = flow.src_ip
            if src not in stats:
                stats[src] = {
                    "flow_count": 0,
                    "unique_dst_ips": set(),
                    "unique_dst_ports": set()
                }
            
            stats[src]["flow_count"] += 1
            stats[src]["unique_dst_ips"].add(flow.dst_ip)
            stats[src]["unique_dst_ports"].add(flow.dst_port)
            
        return stats

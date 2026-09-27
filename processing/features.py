from typing import Dict, Any
from processing.window import WindowSnapshot

class FeatureExtractor:
    """
    Extracts numerical features from a WindowSnapshot for ML inference.
    Produces flow-level feature vectors enriched with window-context aggregations.
    """

    def extract_features(self, snapshot: WindowSnapshot) -> Dict[str, Dict[str, float]]:
        """
        Extracts features for all flows in the given WindowSnapshot.
        Returns a dictionary mapping flow_id to a feature dictionary.

        Features Documented:
        - flow_duration (sec): Duration of flow in this window (source: flow.duration). Purpose: General behavior. Edge-case: 0.0 for single packets.
        - fwd_packet_count (count): Forward packets (source: flow). Purpose: Volume.
        - rev_packet_count (count): Reverse packets (source: flow). Purpose: Volume.
        - fwd_byte_count (bytes): Forward bytes (source: flow). Purpose: Volume.
        - rev_byte_count (bytes): Reverse bytes (source: flow). Purpose: Volume.
        - fwd_bytes_per_sec (bytes/sec): Forward throughput. Purpose: DDoS/Exfil. Edge-case: 0.0 if duration is 0.
        - rev_bytes_per_sec (bytes/sec): Reverse throughput. Purpose: DDoS/Exfil. Edge-case: 0.0 if duration is 0.
        - fwd_pkts_per_sec (pkts/sec): Forward packet rate. Purpose: DDoS. Edge-case: 0.0 if duration is 0.
        - rev_pkts_per_sec (pkts/sec): Reverse packet rate. Purpose: DDoS. Edge-case: 0.0 if duration is 0.
        - byte_ratio (ratio): fwd_bytes / rev_bytes. Purpose: Exfil. Edge-case: Capped at 10000.0 if rev_bytes is 0.
        - is_unidirectional (bool/float): 1.0 if rev_bytes is 0, else 0.0. Purpose: Flag unidirectional flows.
        - src_ip_flow_count (count): Flows from this src_ip in window. Purpose: DDoS/Scan context.
        - src_ip_unique_dst_ips (count): Unique dst IPs hit by src_ip. Purpose: Scan context.
        - src_ip_unique_dst_ports (count): Unique dst ports hit by src_ip. Purpose: Port scan context.
        - is_tcp / is_udp (bool/float): Protocol indicators.
        """
        features = {}

        # 1. Pre-compute window-context statistics (e.g., for Port Scan / DDoS detection)
        src_ip_stats = self._compute_src_ip_stats(snapshot)

        # 2. Compute flow-specific features
        for flow_id, flow in snapshot.flows.items():
            duration = flow.duration

            fwd_bytes = flow.fwd_byte_count
            rev_bytes = flow.rev_byte_count
            fwd_pkts = flow.fwd_packet_count
            rev_pkts = flow.rev_packet_count

            # Flow-level behavior
            # If duration is 0 (e.g. single packet), rates are set to 0.0 to avoid artificial throughput spikes.
            flow_features = {
                "flow_duration": float(duration),
                "fwd_packet_count": float(fwd_pkts),
                "rev_packet_count": float(rev_pkts),
                "fwd_byte_count": float(fwd_bytes),
                "rev_byte_count": float(rev_bytes),
                "fwd_bytes_per_sec": fwd_bytes / duration if duration > 0 else 0.0,
                "rev_bytes_per_sec": rev_bytes / duration if duration > 0 else 0.0,
                "fwd_pkts_per_sec": fwd_pkts / duration if duration > 0 else 0.0,
                "rev_pkts_per_sec": rev_pkts / duration if duration > 0 else 0.0,
                # If reverse bytes is 0, cap ratio at 10000.0 to maintain numerical stability.
                "byte_ratio": fwd_bytes / rev_bytes if rev_bytes > 0 else 10000.0,
                "is_unidirectional": 1.0 if rev_bytes == 0 else 0.0,
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

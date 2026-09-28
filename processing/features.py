"""
processing/features.py
-----------------------
FeatureExtractor — produces ML feature vectors from WindowSnapshot.

FEATURE CONTRACT (Stage 3 — 33 features per flow):
  All values are float.  Missing-because-unavailable uses 0.0 (not NaN).
  Rules for edge cases:
    - Rates at zero duration → 0.0  (D-002)
    - byte_ratio             → compute_byte_ratio()  (D-001)
    - IAT std at n<2         → 0.0
    - TCP flag rates at zero duration → 0.0

Feature groups:
  core_flow    (10): duration, counts, byte counts, byte_ratio
  rates         (4): bytes/s, pkts/s (fwd+rev)
  tcp_flags     (5): syn/fin/rst/ack/psh counts
  iat           (4): fwd/rev IAT mean+std
  pkt_size      (1): mean packet size across flow
  src_context   (3): flow_count, unique_dst_ips, unique_dst_ports (window-level)
  protocol_enc  (2): is_tcp, is_udp
  window_global (4): total_packets, total_bytes, flow_count, packets_per_sec

Total: 33 features
"""
from __future__ import annotations
from typing import Dict, Any, Optional
from processing.window import WindowSnapshot
from processing.feature_math import compute_byte_ratio


class FeatureExtractor:
    """
    Extracts the Stage-3 feature vector from a WindowSnapshot.
    Returns Dict[flow_id, Dict[feature_name, float]].
    """

    def extract_features(self, snapshot: WindowSnapshot) -> Dict[str, Dict[str, float]]:
        features: Dict[str, Dict[str, float]] = {}

        # 1. Window-global metrics (same for every flow in this snapshot)
        win_duration = snapshot.window_end - snapshot.window_start
        global_features = {
            "window_total_packets": float(snapshot.total_packets),
            "window_total_bytes": float(snapshot.total_bytes),
            "window_flow_count": float(snapshot.flow_count),
            "window_packets_per_sec": (
                snapshot.total_packets / win_duration if win_duration > 0 else 0.0
            ),
        }

        # 2. Pre-compute per-source-IP context across entire snapshot
        src_ip_stats = self._compute_src_ip_stats(snapshot)

        # 3. Per-flow features
        for flow_id, flow in snapshot.flows.items():
            duration = flow.duration   # 0.0 for single-packet flows

            fwd_bytes = flow.fwd_byte_count
            rev_bytes = flow.rev_byte_count
            fwd_pkts = flow.fwd_packet_count
            rev_pkts = flow.rev_packet_count
            total_pkts = flow.packet_count

            # --- Rates (0.0 when duration == 0, see D-002) -----------------
            if duration > 0:
                fwd_bytes_per_sec = fwd_bytes / duration
                rev_bytes_per_sec = rev_bytes / duration
                fwd_pkts_per_sec  = fwd_pkts  / duration
                rev_pkts_per_sec  = rev_pkts  / duration
            else:
                fwd_bytes_per_sec = 0.0
                rev_bytes_per_sec = 0.0
                fwd_pkts_per_sec  = 0.0
                rev_pkts_per_sec  = 0.0

            vec: Dict[str, float] = {}

            # --- Group: core_flow -------------------------------------------
            vec["flow_duration"]      = float(duration)
            vec["fwd_packet_count"]   = float(fwd_pkts)
            vec["rev_packet_count"]   = float(rev_pkts)
            vec["total_packet_count"] = float(total_pkts)
            vec["fwd_byte_count"]     = float(fwd_bytes)
            vec["rev_byte_count"]     = float(rev_bytes)
            vec["total_byte_count"]   = float(flow.byte_count)
            # byte_ratio: see D-001 / processing/feature_math.py
            vec["byte_ratio"]         = compute_byte_ratio(fwd_bytes, rev_bytes)

            # --- Group: rates ------------------------------------------------
            vec["fwd_bytes_per_sec"]  = fwd_bytes_per_sec
            vec["rev_bytes_per_sec"]  = rev_bytes_per_sec
            vec["fwd_pkts_per_sec"]   = fwd_pkts_per_sec
            vec["rev_pkts_per_sec"]   = rev_pkts_per_sec

            # --- Group: tcp_flags --------------------------------------------
            vec["syn_count"] = float(flow.syn_count)
            vec["fin_count"] = float(flow.fin_count)
            vec["rst_count"] = float(flow.rst_count)
            vec["ack_count"] = float(flow.ack_count)
            vec["psh_count"] = float(flow.psh_count)

            # --- Group: iat ---------------------------------------------------
            vec["fwd_iat_mean"] = flow.fwd_iat_mean
            vec["fwd_iat_std"]  = flow.fwd_iat_std
            vec["rev_iat_mean"] = flow.rev_iat_mean
            vec["rev_iat_std"]  = flow.rev_iat_std

            # --- Group: pkt_size ---------------------------------------------
            vec["pkt_size_mean"] = flow.pkt_size_mean

            # --- Group: src_context (window-level, same for all flows from same src) ---
            src_ip = flow.src_ip
            ctx = src_ip_stats.get(src_ip, {})
            vec["src_ip_flow_count"]        = float(ctx.get("flow_count", 1))
            vec["src_ip_unique_dst_ips"]    = float(len(ctx.get("unique_dst_ips", set())))
            vec["src_ip_unique_dst_ports"]  = float(len(ctx.get("unique_dst_ports", set())))

            # --- Group: protocol_encoding ------------------------------------
            vec["is_tcp"] = 1.0 if flow.protocol == "TCP" else 0.0
            vec["is_udp"] = 1.0 if flow.protocol == "UDP" else 0.0

            # --- Group: window_global (broadcast per flow) -------------------
            vec.update(global_features)

            features[flow_id] = vec

        return features

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _compute_src_ip_stats(
        self, snapshot: WindowSnapshot
    ) -> Dict[Optional[str], Dict[str, Any]]:
        """
        Aggregate per-source-IP stats across all flows in the snapshot window.
        Returns dict keyed by src_ip.
        """
        stats: Dict[Optional[str], Dict[str, Any]] = {}
        for flow in snapshot.flows.values():
            src = flow.src_ip
            if src not in stats:
                stats[src] = {
                    "flow_count": 0,
                    "unique_dst_ips": set(),
                    "unique_dst_ports": set(),
                }
            stats[src]["flow_count"] += 1
            stats[src]["unique_dst_ips"].add(flow.dst_ip)
            if flow.dst_port is not None:
                stats[src]["unique_dst_ports"].add(flow.dst_port)
        return stats


# ---------------------------------------------------------------------------
# Canonical feature name list (for ML column ordering)
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    # core_flow
    "flow_duration",
    "fwd_packet_count",
    "rev_packet_count",
    "total_packet_count",
    "fwd_byte_count",
    "rev_byte_count",
    "total_byte_count",
    "byte_ratio",
    # rates
    "fwd_bytes_per_sec",
    "rev_bytes_per_sec",
    "fwd_pkts_per_sec",
    "rev_pkts_per_sec",
    # tcp_flags
    "syn_count",
    "fin_count",
    "rst_count",
    "ack_count",
    "psh_count",
    # iat
    "fwd_iat_mean",
    "fwd_iat_std",
    "rev_iat_mean",
    "rev_iat_std",
    # pkt_size
    "pkt_size_mean",
    # src_context
    "src_ip_flow_count",
    "src_ip_unique_dst_ips",
    "src_ip_unique_dst_ports",
    # protocol encoding
    "is_tcp",
    "is_udp",
    # window global
    "window_total_packets",
    "window_total_bytes",
    "window_flow_count",
    "window_packets_per_sec",
]

from detection.detectors.base import BaseDetector, DetectionResult

class ReconnaissanceDetector(BaseDetector):
    """
    Detects Reconnaissance and Port Scanning based on high fan-out behavior.
    Uses canonical features: src_ip_unique_dst_ports and src_ip_unique_dst_ips.
    """
    def __init__(self, port_fanout_threshold: int = 50, ip_fanout_threshold: int = 20, max_ips_for_port_scan: int = 10, max_ports_for_ip_scan: int = 5):
        self.port_fanout_threshold = port_fanout_threshold
        self.ip_fanout_threshold = ip_fanout_threshold
        self.max_ips_for_port_scan = max_ips_for_port_scan
        self.max_ports_for_ip_scan = max_ports_for_ip_scan

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        
        unique_ports = phase6_features.get("src_ip_unique_dst_ports", 0)
        unique_ips = phase6_features.get("src_ip_unique_dst_ips", 0)
        
        # Recon is evaluated per source IP usually, but features are stored in the flow state.
        # To prevent P2P traffic (like BitTorrent) from generating false positives,
        # we require a classic scanning profile:
        # - Port Scan: Many ports scanned on a small number of IPs
        # - IP Scan (Subnet Sweep): Many IPs scanned on a small number of ports (e.g. looking for port 445)
        # P2P typically has a 1:1 ratio of unique IPs to unique ephemeral destination ports.
        
        is_port_scan = (unique_ports >= self.port_fanout_threshold) and (unique_ips <= self.max_ips_for_port_scan)
        is_ip_scan = (unique_ips >= self.ip_fanout_threshold) and (unique_ports <= self.max_ports_for_ip_scan)
        
        if is_port_scan or is_ip_scan:
            reasons = []
            if is_port_scan: reasons.append("high destination-port fan-out (port scan)")
            if is_ip_scan: reasons.append("high destination-ip fan-out (subnet scan)")
            
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="DETECTED",
                threat_type="RECONNAISSANCE",
                severity="HIGH",
                score=1.0,  # Deterministic score based on breach
                detector_name=self.name,
                evidence={
                    "unique_destination_ports": unique_ports,
                    "unique_destination_ips": unique_ips,
                    "reason": " and ".join(reasons)
                }
            )
            
        return DetectionResult(
            flow_id=flow_id,
            timestamp=window_snapshot.window_end,
            status="NOT_DETECTED",
            detector_name=self.name
        )

from typing import Iterable, Dict, Any, List
from dataset.schema import ExternalDatasetRecord, CanonicalLabel

def validate_dataset(records: Iterable[ExternalDatasetRecord]) -> Dict[str, Any]:
    """
    Validates a stream of ExternalDatasetRecord objects.
    Checks chronological ordering, missing values, canonical labels, and provenance.
    """
    summary = {
        "dataset_name": None,
        "total_records": 0,
        "labels": {label.name: 0 for label in CanonicalLabel},
        "missing_core_features": 0,
        "invalid_timestamps": 0,
        "out_of_order_records": 0,
        "time_range": {"start": None, "end": None}
    }
    
    last_timestamp = -1.0
    
    for record in records:
        if summary["dataset_name"] is None:
            summary["dataset_name"] = record.dataset_name
            
        summary["total_records"] += 1
        summary["labels"][record.label.name] += 1
        
        # Temporal checks
        if record.timestamp < 0:
            summary["invalid_timestamps"] += 1
            
        if record.timestamp < last_timestamp:
            summary["out_of_order_records"] += 1
        last_timestamp = record.timestamp
        
        if record.timestamp >= 0:
            if summary["time_range"]["start"] is None or record.timestamp < summary["time_range"]["start"]:
                summary["time_range"]["start"] = record.timestamp
            if summary["time_range"]["end"] is None or record.timestamp > summary["time_range"]["end"]:
                summary["time_range"]["end"] = record.timestamp
            
        # Core feature checks (Phase 6 mapping completeness)
        core_fields = [
            record.fwd_packet_count, record.rev_packet_count,
            record.fwd_byte_count, record.rev_byte_count, record.fwd_bytes_per_sec,
            record.rev_bytes_per_sec, record.fwd_pkts_per_sec, record.rev_pkts_per_sec,
            record.byte_ratio, record.is_unidirectional, record.src_ip_flow_count,
            record.src_ip_unique_dst_ips, record.src_ip_unique_dst_ports,
            record.is_tcp, record.is_udp
        ]
        if any(v is None for v in core_fields):
            summary["missing_core_features"] += 1
            
    return summary

import csv
import logging
from datetime import datetime
from typing import Iterator
from dataset.schema import ExternalDatasetRecord, CanonicalLabel
from dataset.adapter import DatasetAdapter

logger = logging.getLogger(__name__)

class CICIDS2018Adapter(DatasetAdapter):
    """
    Adapter for the CIC-IDS2018 dataset (AWS PCAP version, without Src/Dst IPs).
    Extracts only fields strictly equivalent to Phase 6 features.
    Unsupported/missing fields (like src_ip contextual features) are set to None.
    Extracts additional available raw dataset features into dataset_specific_features.
    """
    
    def map_label(self, original_label: str) -> CanonicalLabel:
        original_label = original_label.strip()
        if original_label.lower() == "benign":
            return CanonicalLabel.BENIGN
        elif original_label.lower() == "bot":
            # CIC-IDS2018 "Bot" labels do not provide flow-level distinction 
            # for C2 beaconing. Mapping to UNKNOWN to avoid claiming C2 without evidence.
            return CanonicalLabel.UNKNOWN
        elif "dos" in original_label.lower():
            return CanonicalLabel.DDOS
        elif "infilteration" in original_label.lower():
            # Infiltration could be EXFILTRATION or just generic intrusion. 
            # Without explicit exfil evidence, mapping to UNKNOWN for now.
            return CanonicalLabel.UNKNOWN
        return CanonicalLabel.UNKNOWN
        
    def get_records(self) -> Iterator[ExternalDatasetRecord]:
        with open(self.file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [name.strip() for name in (reader.fieldnames or [])]
            
            for row_idx, row in enumerate(reader):
                # Mandatory fields - Timestamp
                ts_str = row.get("Timestamp", "")
                try:
                    dt = datetime.strptime(ts_str, "%d/%m/%Y %H:%M:%S")
                    timestamp = dt.timestamp()
                except ValueError:
                    # Invalid timestamp must NOT become 0.0, skip record
                    logger.debug(f"Row {row_idx}: Invalid or missing timestamp '{ts_str}', skipping.")
                    continue
                    
                label_str = row.get("Label", "UNKNOWN").strip()
                canonical_label = self.map_label(label_str)
                
                # Try parsing flow duration (in microseconds for CIC)
                try:
                    duration_sec = float(row.get("Flow Duration", "")) / 1e6
                except ValueError:
                    duration_sec = None
                    
                # Flow level features (Optional mapping to Phase 6)
                try:
                    fwd_pkts = float(row.get("Tot Fwd Pkts", ""))
                    rev_pkts = float(row.get("Tot Bwd Pkts", ""))
                    fwd_bytes = float(row.get("TotLen Fwd Pkts", ""))
                    rev_bytes = float(row.get("TotLen Bwd Pkts", ""))
                except ValueError:
                    fwd_pkts = rev_pkts = fwd_bytes = rev_bytes = None

                if duration_sec is not None and duration_sec > 0:
                    fwd_bytes_per_sec = fwd_bytes / duration_sec if fwd_bytes is not None else None
                    rev_bytes_per_sec = rev_bytes / duration_sec if rev_bytes is not None else None
                    fwd_pkts_per_sec = fwd_pkts / duration_sec if fwd_pkts is not None else None
                    rev_pkts_per_sec = rev_pkts / duration_sec if rev_pkts is not None else None
                else:
                    fwd_bytes_per_sec = rev_bytes_per_sec = fwd_pkts_per_sec = rev_pkts_per_sec = None
                
                if fwd_bytes is not None and rev_bytes is not None:
                    byte_ratio = fwd_bytes / rev_bytes if rev_bytes > 0 else 10000.0
                    is_unidirectional = 1.0 if rev_bytes == 0 else 0.0
                else:
                    byte_ratio = is_unidirectional = None
                
                try:
                    proto = int(row.get("Protocol", -1))
                    is_tcp = 1.0 if proto == 6 else 0.0
                    is_udp = 1.0 if proto == 17 else 0.0
                except ValueError:
                    is_tcp = is_udp = None
                
                # Put all additional keys into dataset_specific_features
                mapped_keys = {"Timestamp", "Label", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Protocol"}
                specific_features = {k: v for k, v in row.items() if k not in mapped_keys}
                
                yield ExternalDatasetRecord(
                    timestamp=timestamp,
                    flow_id=f"cic_row_{row_idx}",
                    dataset_name=self.dataset_name,
                    label=canonical_label,
                    original_label=label_str,
                    
                    # Phase 6 Core Features mapped where available
                    flow_duration=duration_sec,
                    fwd_packet_count=fwd_pkts,
                    rev_packet_count=rev_pkts,
                    fwd_byte_count=fwd_bytes,
                    rev_byte_count=rev_bytes,
                    fwd_bytes_per_sec=fwd_bytes_per_sec,
                    rev_bytes_per_sec=rev_bytes_per_sec,
                    fwd_pkts_per_sec=fwd_pkts_per_sec,
                    rev_pkts_per_sec=rev_pkts_per_sec,
                    byte_ratio=byte_ratio,
                    is_unidirectional=is_unidirectional,
                    is_tcp=is_tcp,
                    is_udp=is_udp,
                    
                    # Contextual features strictly missing
                    src_ip_flow_count=None,
                    src_ip_unique_dst_ips=None,
                    src_ip_unique_dst_ports=None,
                    
                    # Native dataset features
                    dataset_specific_features=specific_features
                )

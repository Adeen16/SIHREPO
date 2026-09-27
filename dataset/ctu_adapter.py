import csv
import logging
from datetime import datetime
from typing import Iterator
from dataset.schema import ExternalDatasetRecord, CanonicalLabel
from dataset.adapter import DatasetAdapter

logger = logging.getLogger(__name__)

class CTU13Adapter(DatasetAdapter):
    """
    Adapter for the CTU-13 dataset (.binetflow format).
    Extracts fields strictly equivalent to Phase 6 features.
    Unsupported/missing fields (like directional packet counts) are set to None.
    Extracts additional available raw dataset features into dataset_specific_features.
    """

    def map_label(self, original_label: str) -> CanonicalLabel:
        label_lower = original_label.lower()
        if "background" in label_lower or "normal" in label_lower:
            return CanonicalLabel.BENIGN

        if "botnet" in label_lower:
            # Defensible evidence mapping
            if "cc" in label_lower or "c&c" in label_lower or "beacon" in label_lower:
                return CanonicalLabel.C2_BEACONING
            elif "ddos" in label_lower or "dos" in label_lower:
                return CanonicalLabel.DDOS
            elif "scan" in label_lower:
                return CanonicalLabel.RECON
            else:
                # E.g., SPAM or generically tagged botnet
                return CanonicalLabel.UNKNOWN

        return CanonicalLabel.UNKNOWN

    def get_records(self) -> Iterator[ExternalDatasetRecord]:
        with open(self.file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [name.strip() for name in (reader.fieldnames or [])]

            for row_idx, row in enumerate(reader):
                ts_str = row.get("StartTime", "")
                try:
                    # e.g., "2011/08/10 09:46:53.047277"
                    dt = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")
                    timestamp = dt.timestamp()
                except ValueError:
                    logger.debug(f"Row {row_idx}: Invalid or missing StartTime '{ts_str}', skipping.")
                    continue

                label_str = row.get("Label", "UNKNOWN").strip()
                canonical_label = self.map_label(label_str)

                try:
                    duration_sec = float(row.get("Dur", ""))
                except ValueError:
                    duration_sec = None

                try:
                    tot_bytes = float(row.get("TotBytes", ""))
                    fwd_bytes = float(row.get("SrcBytes", ""))
                    rev_bytes = tot_bytes - fwd_bytes
                except ValueError:
                    tot_bytes = fwd_bytes = rev_bytes = None

                if duration_sec is not None and duration_sec > 0:
                    fwd_bytes_per_sec = fwd_bytes / duration_sec if fwd_bytes is not None else None
                    rev_bytes_per_sec = rev_bytes / duration_sec if rev_bytes is not None else None
                else:
                    fwd_bytes_per_sec = rev_bytes_per_sec = None

                if fwd_bytes is not None and rev_bytes is not None:
                    byte_ratio = fwd_bytes / rev_bytes if rev_bytes > 0 else 10000.0
                    is_unidirectional = 1.0 if rev_bytes == 0 else 0.0
                else:
                    byte_ratio = is_unidirectional = None

                proto_str = row.get("Proto", "").lower().strip()
                if proto_str == "tcp":
                    is_tcp = 1.0; is_udp = 0.0
                elif proto_str == "udp":
                    is_tcp = 0.0; is_udp = 1.0
                elif proto_str:
                    is_tcp = 0.0; is_udp = 0.0
                else:
                    is_tcp = is_udp = None

                src_ip = row.get("SrcAddr", None)
                dst_ip = row.get("DstAddr", None)
                try:
                    src_port = int(row.get("Sport", ""))
                except ValueError:
                    src_port = None
                try:
                    dst_port = int(row.get("Dport", ""))
                except ValueError:
                    dst_port = None

                mapped_keys = {"StartTime", "Dur", "TotBytes", "SrcBytes", "Proto", "SrcAddr", "DstAddr", "Sport", "Dport", "Label"}
                specific_features = {k: v for k, v in row.items() if k not in mapped_keys}

                yield ExternalDatasetRecord(
                    timestamp=timestamp,
                    flow_id=f"ctu_row_{row_idx}_{src_ip}_{dst_ip}",
                    dataset_name=self.dataset_name,
                    label=canonical_label,
                    original_label=label_str,

                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str if proto_str else None,

                    # Core Phase 6 Features (mapped where available)
                    flow_duration=duration_sec,
                    fwd_packet_count=None,
                    rev_packet_count=None,
                    fwd_byte_count=fwd_bytes,
                    rev_byte_count=rev_bytes,
                    fwd_bytes_per_sec=fwd_bytes_per_sec,
                    rev_bytes_per_sec=rev_bytes_per_sec,
                    fwd_pkts_per_sec=None,
                    rev_pkts_per_sec=None,
                    byte_ratio=byte_ratio,
                    is_unidirectional=is_unidirectional,
                    is_tcp=is_tcp,
                    is_udp=is_udp,

                    # Contextual features missing in CSV are left as None
                    src_ip_flow_count=None,
                    src_ip_unique_dst_ips=None,
                    src_ip_unique_dst_ports=None,

                    dataset_specific_features=specific_features
                )

"""
dataset/cic_adapter.py
-----------------------
Streaming adapter for CIC-IDS2018 "TrafficForML" CSV files.

Design decisions (see docs/DECISIONS.md):
- Timestamps parsed as UTC-explicit via dataset.timeutil.parse_cic_ts.
  Zero timestamp from a parse failure → row rejected (bad_timestamp), never defaulted.
- NaN/Inf and negative values → rejected (not imputed).
- Repeated header rows (duplicate column names in body) → skipped with count.
- CIC-2018 has no IP columns → src_ip_* features stay None, feature_source='dataset_native'.
- Flow duration from 'Flow Duration' column (microseconds → seconds).
- Byte-count note: CICFlowMeter 'TotLen Fwd/Bwd Pkts' are payload bytes;
  this differs from Phase-3 pcap_reader which uses total packet length.
  Absolute byte-magnitude features should NOT be compared cross-source.
  is_tcp/is_udp derived from 'Protocol' numeric column: 6→tcp, 17→udp.
- Adapter is a generator (lazy); never loads the full file into memory.
"""
from __future__ import annotations
import csv
import math
import pathlib
from typing import Generator, Optional
import pathlib

from dataset.schema import UnifiedFeatureRecord, CanonicalLabel
from dataset.timeutil import parse_cic_ts
from dataset.stats import AdapterStats
from dataset.label_mapper import map_label, _load_rules
from dataset.validation import validate_record
from processing.feature_math import compute_byte_ratio


# Required columns that must be present
_REQUIRED_COLS = {"Timestamp", "Label"}

# CIC-IDS2018 protocol numeric codes
_PROTO_TCP = 6
_PROTO_UDP = 17

# Load label rules once at module import (lazy on first adapter creation)
_CIC_RULES_PATH = pathlib.Path(__file__).parent / "label_maps" / "cic2018.yaml"


class CICAdapter:
    """
    Streaming adapter for CIC-IDS2018 TrafficForML CSV files.

    Usage:
        adapter = CICAdapter(path)
        for record in adapter:
            ...
        print(adapter.stats)
    """

    def __init__(self, csv_path: pathlib.Path | str) -> None:
        self._path = pathlib.Path(csv_path)
        self._rules = _load_rules(_CIC_RULES_PATH)
        self.stats = AdapterStats()

    def __iter__(self) -> Generator[UnifiedFeatureRecord, None, None]:
        header: Optional[list] = None
        seen_rows: set = set()  # for duplicate detection (limited; see note)

        with open(self._path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for raw_row in reader:
                self.stats.rows_read += 1

                # Detect and skip repeated header rows
                if header is None:
                    header = [col.strip() for col in raw_row]
                    continue
                if raw_row and raw_row[0].strip() == header[0]:
                    self.stats.reject("duplicate_header_row")
                    continue

                if len(raw_row) != len(header):
                    self.stats.reject("missing_required_field")
                    continue

                row = dict(zip(header, (v.strip() for v in raw_row)))

                # Missing required fields
                for req in _REQUIRED_COLS:
                    if req not in row or not row[req]:
                        self.stats.reject("missing_required_field")
                        break
                else:
                    rec = self._parse_row(row)
                    if rec is None:
                        continue  # rejection already counted in _parse_row

                    # Duplicate row detection (hash key fields)
                    row_key = (row.get("Timestamp", ""), row.get("Dst Port", ""),
                               row.get("Flow Duration", ""), row.get("Label", ""))
                    if row_key in seen_rows:
                        self.stats.reject("duplicate_row")
                        continue
                    seen_rows.add(row_key)

                    is_valid, reason = validate_record(rec)
                    if not is_valid:
                        self.stats.reject(reason)
                        continue

                    self.stats.rows_yielded += 1
                    self.stats.distinct_labels[rec.label.name] += 1
                    yield rec

    def _parse_row(self, row: dict) -> Optional[UnifiedFeatureRecord]:
        """Parse one CSV row dict into a UnifiedFeatureRecord or None (rejected)."""
        # Timestamp
        try:
            ts = parse_cic_ts(row["Timestamp"])
        except ValueError:
            self.stats.reject("bad_timestamp")
            return None

        if ts <= 0.0:
            self.stats.reject("bad_timestamp")
            return None

        # Duration: microseconds → seconds
        try:
            duration_s = float(row.get("Flow Duration", "0")) / 1_000_000.0
        except (ValueError, TypeError):
            self.stats.reject("bad_numeric")
            return None

        if math.isnan(duration_s) or math.isinf(duration_s):
            self.stats.reject("nan_or_inf")
            return None
        if duration_s < 0:
            self.stats.reject("negative_value")
            return None

        flow_start = ts
        flow_end = ts + duration_s

        # Byte / packet counts
        def safe_float(key: str) -> Optional[float]:
            try:
                v = float(row.get(key, "nan"))
                if math.isnan(v) or math.isinf(v):
                    return None
                return v
            except (ValueError, TypeError):
                return None

        fwd_pkts = safe_float("Tot Fwd Pkts")
        rev_pkts = safe_float("Tot Bwd Pkts")
        fwd_bytes = safe_float("TotLen Fwd Pkts")
        rev_bytes = safe_float("TotLen Bwd Pkts")

        # Any None/negative → reject
        for name, val in [("fwd_pkts", fwd_pkts), ("rev_pkts", rev_pkts),
                           ("fwd_bytes", fwd_bytes), ("rev_bytes", rev_bytes)]:
            if val is None:
                self.stats.reject("nan_or_inf")
                return None
            if val < 0:
                self.stats.reject("negative_value")
                return None

        # Protocol
        proto_raw = safe_float("Protocol")
        if proto_raw is None:
            protocol = "other"
            is_tcp, is_udp = 0.0, 0.0
        elif int(proto_raw) == _PROTO_TCP:
            protocol, is_tcp, is_udp = "tcp", 1.0, 0.0
        elif int(proto_raw) == _PROTO_UDP:
            protocol, is_tcp, is_udp = "udp", 0.0, 1.0
        else:
            protocol, is_tcp, is_udp = "other", 0.0, 0.0

        dst_port_raw = safe_float("Dst Port")
        dst_port = int(dst_port_raw) if dst_port_raw is not None else None

        # Label
        raw_label = row.get("Label", "")
        canonical, label_source, label_group, _ = map_label(raw_label, self._rules)

        # Rates
        if duration_s > 0:
            fwd_bps = fwd_bytes / duration_s
            rev_bps = rev_bytes / duration_s
            fwd_pps = fwd_pkts / duration_s
            rev_pps = rev_pkts / duration_s
        else:
            fwd_bps = rev_bps = fwd_pps = rev_pps = 0.0

        return UnifiedFeatureRecord(
            timestamp=flow_start,
            flow_start=flow_start,
            flow_end=flow_end,
            window_start=flow_start,
            window_end=flow_end,
            dst_port=dst_port,
            protocol=protocol,
            is_tcp=is_tcp,
            is_udp=is_udp,
            flow_duration=duration_s,
            fwd_packet_count=fwd_pkts,
            rev_packet_count=rev_pkts,
            fwd_byte_count=fwd_bytes,
            rev_byte_count=rev_bytes,
            fwd_bytes_per_sec=fwd_bps,
            rev_bytes_per_sec=rev_bps,
            fwd_pkts_per_sec=fwd_pps,
            rev_pkts_per_sec=rev_pps,
            byte_ratio=compute_byte_ratio(int(fwd_bytes), int(rev_bytes)),
            # src_ip_* not available in CIC-2018 CSV
            src_ip_flow_count=None,
            src_ip_unique_dst_ips=None,
            src_ip_unique_dst_ports=None,
            feature_source="dataset_native",
            label_source=label_source,
            label_group=label_group,
            label=canonical,
        )

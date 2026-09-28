"""
dataset/ctu_adapter.py
-----------------------
Streaming adapter for CTU-13 .binetflow CSV files.

Design decisions (see docs/DECISIONS.md):
- Timestamps parsed as UTC-explicit via dataset.timeutil.parse_ctu_ts.
  Zero timestamp from a parse failure → row rejected, never defaulted.
- Background traffic → UNLABELED; excluded from supervised training by default.
- CTU-13 has SrcAddr/DstAddr/Dport → src_ip_* context can be computed
  by RecordWindowAggregator (correcting phase_7b_audit.md §C.6 claim).
- Rev bytes = TotBytes - SrcBytes; reject if negative.
- ICMP rows (no ports) → kept with protocol='icmp', is_tcp=is_udp=0.
  Hex ports handled; blank ports → None.
- 'Dir' column: not used for canonical direction (bidirectional key used).
- TotPkts retained in optional_features['total_packets'].
- Adapter is a generator (lazy); never loads full file into memory.
"""
from __future__ import annotations
import csv
import math
import pathlib
from typing import Generator, Optional

from dataset.schema import UnifiedFeatureRecord, CanonicalLabel
from dataset.timeutil import parse_ctu_ts
from dataset.stats import AdapterStats
from dataset.label_mapper import map_label, _load_rules
from dataset.validation import validate_record
from processing.feature_math import compute_byte_ratio


_CTU_RULES_PATH = pathlib.Path(__file__).parent / "label_maps" / "ctu13.yaml"

_REQUIRED_COLS = {"StartTime", "Label"}


def _parse_port(raw: str, proto: str) -> Optional[int]:
    """Parse a port field that may be hex, decimal, or empty."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        if raw.startswith("0x") or raw.startswith("0X"):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return None


class CTUAdapter:
    """
    Streaming adapter for CTU-13 .binetflow files.

    Usage:
        adapter = CTUAdapter(path)
        for record in adapter:
            ...
        print(adapter.stats)
    """

    def __init__(self, binetflow_path: pathlib.Path | str) -> None:
        self._path = pathlib.Path(binetflow_path)
        self._rules = _load_rules(_CTU_RULES_PATH)
        self.stats = AdapterStats()

    def __iter__(self) -> Generator[UnifiedFeatureRecord, None, None]:
        header: Optional[list] = None
        seen_rows: set = set()

        with open(self._path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for raw_row in reader:
                self.stats.rows_read += 1

                if header is None:
                    header = [col.strip() for col in raw_row]
                    continue
                # Repeated header rows
                if raw_row and raw_row[0].strip() == header[0]:
                    self.stats.reject("duplicate_header_row")
                    continue

                if len(raw_row) < len(header):
                    self.stats.reject("missing_required_field")
                    continue

                row = dict(zip(header, (v.strip() for v in raw_row)))

                for req in _REQUIRED_COLS:
                    if req not in row or not row[req]:
                        self.stats.reject("missing_required_field")
                        break
                else:
                    rec = self._parse_row(row)
                    if rec is None:
                        continue

                    row_key = (row.get("StartTime", ""), row.get("SrcAddr", ""),
                               row.get("DstAddr", ""), row.get("Dport", ""),
                               row.get("Label", ""))
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
        # Timestamp
        try:
            ts = parse_ctu_ts(row["StartTime"])
        except ValueError:
            self.stats.reject("bad_timestamp")
            return None
        if ts <= 0.0:
            self.stats.reject("bad_timestamp")
            return None

        # Duration
        try:
            duration_s = float(row.get("Dur", "0") or "0")
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

        # Protocol
        proto_raw = row.get("Proto", "").lower()
        if proto_raw == "tcp":
            protocol, is_tcp, is_udp = "tcp", 1.0, 0.0
        elif proto_raw == "udp":
            protocol, is_tcp, is_udp = "udp", 0.0, 1.0
        elif proto_raw in ("icmp", "icmp6", "icmpv6"):
            protocol, is_tcp, is_udp = "icmp", 0.0, 0.0
        else:
            protocol, is_tcp, is_udp = "other", 0.0, 0.0

        # Ports — ICMP rows have no ports
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        if protocol not in ("icmp",):
            src_port = _parse_port(row.get("Sport", ""), protocol)
            dst_port = _parse_port(row.get("Dport", ""), protocol)

        # Byte counts
        def safe_float(key: str) -> Optional[float]:
            try:
                v = float(row.get(key, "nan") or "nan")
                if math.isnan(v) or math.isinf(v):
                    return None
                return v
            except (ValueError, TypeError):
                return None

        tot_bytes = safe_float("TotBytes")
        src_bytes = safe_float("SrcBytes")
        tot_pkts = safe_float("TotPkts")

        if tot_bytes is None or src_bytes is None:
            self.stats.reject("nan_or_inf")
            return None
        if tot_bytes < 0 or src_bytes < 0:
            self.stats.reject("negative_value")
            return None

        fwd_bytes = src_bytes
        rev_bytes_val = tot_bytes - src_bytes
        if rev_bytes_val < 0:
            self.stats.reject("negative_value")
            return None
        rev_bytes = rev_bytes_val

        # Rates
        if duration_s > 0:
            fwd_bps = fwd_bytes / duration_s
            rev_bps = rev_bytes / duration_s
        else:
            fwd_bps = rev_bps = 0.0

        # Packet counts — only total available from CTU
        total_pkts = tot_pkts if tot_pkts is not None else 0.0
        # fwd/rev packet split unavailable from record format
        fwd_pkts = total_pkts  # approximation: assume all packets are forward
        rev_pkts = 0.0         # documented as unavailable

        if duration_s > 0:
            fwd_pps = fwd_pkts / duration_s
            rev_pps = 0.0
        else:
            fwd_pps = rev_pps = 0.0

        # IPs
        src_ip = row.get("SrcAddr") or None
        dst_ip = row.get("DstAddr") or None

        # Label
        raw_label = row.get("Label", "")
        canonical, label_source, label_group, _ = map_label(raw_label, self._rules)

        return UnifiedFeatureRecord(
            timestamp=flow_start,
            flow_start=flow_start,
            flow_end=flow_end,
            window_start=flow_start,
            window_end=flow_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
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
            # src_ip_* populated by RecordWindowAggregator downstream
            src_ip_flow_count=None,
            src_ip_unique_dst_ips=None,
            src_ip_unique_dst_ports=None,
            feature_source="dataset_native",
            label_source=label_source,
            label_group=label_group,
            label=canonical,
            optional_features={"total_packets": total_pkts} if tot_pkts is not None else {},
        )

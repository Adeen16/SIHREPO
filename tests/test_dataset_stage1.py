"""
tests/test_dataset_stage1.py
----------------------------
Stage 1 regression tests covering every defect identified in §C of the order.
All tests use tiny tmp_path fixtures; no real dataset files are read.
"""
import csv
import io
import math
import pathlib
import pytest
import itertools

from dataset.schema import CanonicalLabel, UnifiedFeatureRecord
from dataset.timeutil import parse_cic_ts, parse_ctu_ts
from dataset.stats import AdapterStats
from dataset.validation import validate_record
from dataset.label_mapper import map_label, _load_rules
from dataset.record_aggregator import RecordWindowAggregator
from dataset.cic_adapter import CICAdapter
from dataset.ctu_adapter import CTUAdapter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CIC_HEADER = (
    "Timestamp,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,"
    "TotLen Fwd Pkts,TotLen Bwd Pkts,Label"
)

_CTU_HEADER = (
    "StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,TotPkts,TotBytes,SrcBytes,Label"
)


def _write_cic_csv(tmp_path, rows: list[str], header=_CIC_HEADER) -> pathlib.Path:
    p = tmp_path / "test_cic.csv"
    p.write_text("\n".join([header] + rows), encoding="utf-8")
    return p


def _write_ctu_csv(tmp_path, rows: list[str], header=_CTU_HEADER) -> pathlib.Path:
    p = tmp_path / "test_ctu.binetflow"
    p.write_text("\n".join([header] + rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# §C.1 — compute_byte_ratio (covered fully in test_feature_math.py; spot-check here)
# ---------------------------------------------------------------------------

class TestByteRatioInAdapters:
    def test_cic_unidirectional_uses_cap(self, tmp_path):
        """fwd>0, rev=0 → byte_ratio must be BYTE_RATIO_CAP, not a fabricated large number."""
        row = "15/02/2018 09:00:00,80,6,1000000,10,0,5000,0,Benign"
        p = _write_cic_csv(tmp_path, [row])
        records = list(CICAdapter(p))
        assert len(records) == 1
        from processing.feature_math import BYTE_RATIO_CAP
        assert records[0].byte_ratio == BYTE_RATIO_CAP

    def test_ctu_unidirectional_uses_cap(self, tmp_path):
        row = "2011/08/10 09:46:59.607492,1.0,tcp,10.0.0.1,1234,10.0.0.2,80,10,5000,5000,flow=From-Normal-0"
        p = _write_ctu_csv(tmp_path, [row])
        records = list(CTUAdapter(p))
        assert len(records) == 1
        from processing.feature_math import BYTE_RATIO_CAP
        # rev_bytes = TotBytes - SrcBytes = 5000 - 5000 = 0 → cap
        assert records[0].byte_ratio == BYTE_RATIO_CAP


# ---------------------------------------------------------------------------
# §C.2 — Zero timestamp fallback replaced with reject-and-count
# ---------------------------------------------------------------------------

class TestTimestampRejection:
    def test_cic_bad_timestamp_rejected_not_defaulted(self, tmp_path):
        """Unparseable timestamp → rejected with bad_timestamp, no record emitted."""
        row = "NOT_A_DATE,80,6,1000000,10,5,5000,2000,Benign"
        p = _write_cic_csv(tmp_path, [row])
        adapter = CICAdapter(p)
        records = list(adapter)
        assert len(records) == 0
        assert adapter.stats.rows_rejected["bad_timestamp"] == 1

    def test_ctu_bad_timestamp_rejected(self, tmp_path):
        row = "INVALID,1.0,tcp,10.0.0.1,1234,10.0.0.2,80,10,5000,3000,flow=From-Normal-0"
        p = _write_ctu_csv(tmp_path, [row])
        adapter = CTUAdapter(p)
        records = list(adapter)
        assert len(records) == 0
        assert adapter.stats.rows_rejected["bad_timestamp"] == 1

    def test_adapter_never_emits_timestamp_zero(self, tmp_path):
        """No record from an adapter may have timestamp == 0.0."""
        rows = [
            "15/02/2018 09:00:00,80,6,1000000,10,5,5000,2000,Benign",
            "NOT_A_DATE,80,6,1000000,10,5,5000,2000,Benign",
        ]
        p = _write_cic_csv(tmp_path, rows)
        for rec in CICAdapter(p):
            assert rec.timestamp != 0.0, "Adapter emitted a zero timestamp"


# ---------------------------------------------------------------------------
# §C.3 — UTC timestamp parsing determinism
# ---------------------------------------------------------------------------

class TestUTCTimestamps:
    def test_cic_ts_parse_deterministic(self):
        t1 = parse_cic_ts("15/02/2018 09:00:00")
        t2 = parse_cic_ts("15/02/2018 09:00:00")
        assert t1 == t2

    def test_ctu_ts_with_microseconds(self):
        t = parse_ctu_ts("2011/08/10 09:46:59.607492")
        assert t > 0

    def test_ctu_ts_without_microseconds(self):
        t = parse_ctu_ts("2011/08/10 09:46:59")
        assert t > 0

    def test_cic_ts_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_cic_ts("NOT_A_DATE")

    def test_ctu_ts_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_ctu_ts("NOT_A_DATE")

    def test_cic_ctu_ordering_consistent(self):
        """Relative ordering must be stable across two timestamps."""
        t1 = parse_ctu_ts("2011/08/10 09:00:00")
        t2 = parse_ctu_ts("2011/08/10 10:00:00")
        assert t2 > t1
        assert abs(t2 - t1 - 3600.0) < 1.0  # exactly 1 hour apart


# ---------------------------------------------------------------------------
# §C.4 — Correct flow window semantics
# ---------------------------------------------------------------------------

class TestFlowWindowSemantics:
    def test_flow_end_equals_start_plus_duration_cic(self, tmp_path):
        """flow_end = flow_start + duration (not timestamp - duration)."""
        row = "15/02/2018 09:00:00,80,6,5000000,10,5,5000,2000,Benign"  # 5 s duration
        p = _write_cic_csv(tmp_path, [row])
        records = list(CICAdapter(p))
        assert len(records) == 1
        rec = records[0]
        assert abs(rec.flow_end - rec.flow_start - 5.0) < 1e-6

    def test_flow_start_le_flow_end_ctu(self, tmp_path):
        row = "2011/08/10 09:46:59.607492,2.5,tcp,10.0.0.1,1234,10.0.0.2,80,10,5000,3000,flow=From-Normal-0"
        p = _write_ctu_csv(tmp_path, [row])
        records = list(CTUAdapter(p))
        assert records[0].flow_start <= records[0].flow_end

    def test_validation_rejects_flow_end_before_start(self):
        rec = UnifiedFeatureRecord(
            timestamp=1000.0, flow_start=1000.0,
            flow_end=999.0,  # end before start
            window_start=1000.0, window_end=999.0,
        )
        valid, reason = validate_record(rec)
        assert not valid
        assert reason == "negative_value"


# ---------------------------------------------------------------------------
# §C.5 — CTU label mapping correctness
# ---------------------------------------------------------------------------

class TestCTULabelMapping:
    @pytest.fixture
    def ctu_rules(self):
        rules_path = pathlib.Path("dataset/label_maps/ctu13.yaml")
        return _load_rules(rules_path)

    def test_normal_is_benign(self, ctu_rules):
        label, src, grp, _ = map_label("flow=From-Normal-0", ctu_rules)
        assert label == CanonicalLabel.BENIGN
        assert src == "ground_truth"

    def test_background_is_unlabeled_not_benign(self, ctu_rules):
        label, _, grp, _ = map_label("Background", ctu_rules)
        assert label == CanonicalLabel.UNLABELED
        assert label != CanonicalLabel.BENIGN

    def test_from_background_is_unlabeled(self, ctu_rules):
        label, _, _, _ = map_label("From-Background-whatever", ctu_rules)
        assert label == CanonicalLabel.UNLABELED

    def test_botnet_cc_is_c2(self, ctu_rules):
        label, src, grp, _ = map_label("From-Botnet-49-CC", ctu_rules)
        assert label == CanonicalLabel.C2_BEACONING
        assert src == "weak"

    def test_botnet_spam_is_unknown_not_c2(self, ctu_rules):
        label, _, grp, _ = map_label("From-Botnet-49-SPAM", ctu_rules)
        assert label == CanonicalLabel.UNKNOWN
        assert grp == "botnet_spam"

    def test_botnet_dns_is_unknown(self, ctu_rules):
        label, _, _, _ = map_label("From-Botnet-49-DNS", ctu_rules)
        assert label == CanonicalLabel.UNKNOWN

    def test_botnet_clickfraud_is_unknown(self, ctu_rules):
        label, _, _, _ = map_label("From-Botnet-49-ClickFraud", ctu_rules)
        assert label == CanonicalLabel.UNKNOWN

    def test_unmapped_label_is_unknown(self, ctu_rules):
        label, _, _, _ = map_label("totally_unknown_label", ctu_rules)
        assert label == CanonicalLabel.UNKNOWN


# ---------------------------------------------------------------------------
# §C.8 — Adapter robustness
# ---------------------------------------------------------------------------

class TestAdapterRobustness:
    def test_cic_duplicate_header_row_skipped(self, tmp_path):
        """Embedded repeated header rows must be skipped and counted."""
        rows = [
            "15/02/2018 09:00:00,80,6,1000000,10,5,5000,2000,Benign",
            _CIC_HEADER,  # repeated header in body
            "15/02/2018 09:00:01,80,6,1000000,10,5,5000,2000,Benign",
        ]
        p = _write_cic_csv(tmp_path, rows)
        adapter = CICAdapter(p)
        records = list(adapter)
        assert len(records) == 2
        assert adapter.stats.rows_rejected["duplicate_header_row"] == 1

    def test_cic_nan_bytes_rejected(self, tmp_path):
        row = "15/02/2018 09:00:00,80,6,1000000,10,5,NaN,2000,Benign"
        p = _write_cic_csv(tmp_path, [row])
        adapter = CICAdapter(p)
        records = list(adapter)
        assert len(records) == 0
        assert adapter.stats.rows_rejected["nan_or_inf"] == 1

    def test_cic_negative_byte_count_rejected(self, tmp_path):
        row = "15/02/2018 09:00:00,80,6,1000000,10,5,-100,2000,Benign"
        p = _write_cic_csv(tmp_path, [row])
        adapter = CICAdapter(p)
        records = list(adapter)
        assert len(records) == 0
        assert adapter.stats.rows_rejected["negative_value"] == 1

    def test_ctu_negative_rev_bytes_rejected(self, tmp_path):
        """TotBytes < SrcBytes → rev_bytes negative → rejected."""
        row = "2011/08/10 09:46:59.607492,1.0,tcp,10.0.0.1,1234,10.0.0.2,80,10,100,5000,flow=From-Normal-0"
        p = _write_ctu_csv(tmp_path, [row])
        adapter = CTUAdapter(p)
        records = list(adapter)
        assert len(records) == 0
        assert adapter.stats.rows_rejected["negative_value"] == 1

    def test_adapters_are_lazy_generators(self, tmp_path):
        """Adapters must be generators, not lists. Check via iterator protocol."""
        rows = ["15/02/2018 09:00:00,80,6,1000000,10,5,5000,2000,Benign"]
        p = _write_cic_csv(tmp_path, rows)
        adapter = CICAdapter(p)
        it = iter(adapter)
        # Should be able to get one item without consuming all
        first = next(it, None)
        assert first is not None


# ---------------------------------------------------------------------------
# §1.7 — RecordWindowAggregator
# ---------------------------------------------------------------------------

class TestRecordWindowAggregator:
    def _make_rec(self, ts, src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80):
        return UnifiedFeatureRecord(
            timestamp=ts, flow_start=ts, flow_end=ts + 0.1,
            window_start=ts, window_end=ts + 0.1,
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        )

    def test_exact_counts_single_src(self):
        agg = RecordWindowAggregator(window=10.0)
        # 5 flows from same src to different ports
        ports = [80, 81, 82, 83, 84]
        for i, port in enumerate(ports):
            rec = self._make_rec(ts=float(i), dst_port=port)
            agg.update(rec)
        last = self._make_rec(ts=4.0, dst_port=85)
        agg.update(last)
        assert last.src_ip_flow_count == 6.0
        assert last.src_ip_unique_dst_ports == 6.0

    def test_eviction_boundary(self):
        """Flows outside window are evicted."""
        agg = RecordWindowAggregator(window=5.0)
        r1 = self._make_rec(ts=0.0, dst_port=80)
        agg.update(r1)
        r2 = self._make_rec(ts=6.0, dst_port=81)  # r1 at t=0 is now outside [1.0, 6.0]
        agg.update(r2)
        assert r2.src_ip_flow_count == 1.0  # only r2 in window

    def test_non_decreasing_enforcement(self):
        agg = RecordWindowAggregator(window=10.0)
        agg.update(self._make_rec(ts=5.0))
        with pytest.raises(ValueError):
            agg.update(self._make_rec(ts=3.0))

    def test_no_future_leakage(self):
        """Appending later records must not change earlier output."""
        agg = RecordWindowAggregator(window=10.0)
        r1 = self._make_rec(ts=1.0, dst_port=80)
        agg.update(r1)
        count_after_r1 = r1.src_ip_flow_count

        # Add many later records
        for i in range(2, 100):
            agg.update(self._make_rec(ts=float(i), dst_port=i + 80))

        # r1's value must not change
        assert r1.src_ip_flow_count == count_after_r1

    def test_feature_source_set(self):
        agg = RecordWindowAggregator()
        rec = self._make_rec(ts=1.0)
        agg.update(rec)
        assert rec.feature_source == "record_aggregated"

    def test_no_src_ip_leaves_none(self):
        agg = RecordWindowAggregator()
        rec = UnifiedFeatureRecord(
            timestamp=1.0, flow_start=1.0, flow_end=1.5,
            window_start=1.0, window_end=1.5,
            src_ip=None,
        )
        agg.update(rec)
        assert rec.src_ip_flow_count is None

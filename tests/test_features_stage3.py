"""
tests/test_features_stage3.py
------------------------------
Stage 3 tests for the extended FeatureExtractor.
Covers all new feature groups: tcp_flags, iat, pkt_size, window_global.
"""
import math
import pytest
from processing.flow import FlowState, FlowProcessor
from processing.window import WindowSnapshot
from processing.features import FeatureExtractor, FEATURE_NAMES
from processing.feature_math import BYTE_RATIO_CAP
from ingestion.packet_event import PacketEvent


def _make_flow(flow_id="f1", src_ip="10.0.0.1", dst_ip="10.0.0.2",
               src_port=1234, dst_port=80, protocol="TCP",
               first_seen=0.0, last_seen=5.0,
               packet_count=10, byte_count=1000,
               fwd_packet_count=6, rev_packet_count=4,
               fwd_byte_count=600, rev_byte_count=400,
               syn_count=1, fin_count=1, rst_count=0,
               ack_count=8, psh_count=4,
               fwd_iat_list=None, rev_iat_list=None) -> FlowState:
    f = FlowState(
        flow_id=flow_id, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, protocol=protocol,
        first_seen=first_seen, last_seen=last_seen,
        packet_count=packet_count, byte_count=byte_count,
        fwd_packet_count=fwd_packet_count, rev_packet_count=rev_packet_count,
        fwd_byte_count=fwd_byte_count, rev_byte_count=rev_byte_count,
        syn_count=syn_count, fin_count=fin_count, rst_count=rst_count,
        ack_count=ack_count, psh_count=psh_count,
    )
    if fwd_iat_list:
        f.fwd_iat_list = fwd_iat_list
    if rev_iat_list:
        f.rev_iat_list = rev_iat_list
    return f


def _snap(flow=None, **kwargs):
    flows = {}
    if flow:
        flows[flow.flow_id] = flow
    win_start = kwargs.pop("window_start", 0.0)
    win_end   = kwargs.pop("window_end", 10.0)
    return WindowSnapshot(
        window_start=win_start, window_end=win_end,
        total_packets=kwargs.pop("total_packets", 100),
        total_bytes=kwargs.pop("total_bytes", 10000),
        flow_count=len(flows),
        flows=flows,
    )


class TestFeatureContractCompleteness:
    def test_all_feature_names_present(self):
        """Every flow vector must contain all FEATURE_NAMES keys."""
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow, total_packets=10, total_bytes=1000)
        features = extractor.extract_features(snap)
        vec = features[flow.flow_id]
        missing = [k for k in FEATURE_NAMES if k not in vec]
        assert not missing, f"Missing features: {missing}"

    def test_all_values_float(self):
        """All feature values must be Python floats."""
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        bad = {k: type(v) for k, v in vec.items() if not isinstance(v, float)}
        assert not bad, f"Non-float values: {bad}"

    def test_no_nan_no_inf(self):
        """No NaN or Inf values in any feature vector."""
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        for k, v in vec.items():
            assert math.isfinite(v), f"Feature '{k}' is not finite: {v}"


class TestTCPFlagFeatures:
    def test_syn_count_propagated(self):
        extractor = FeatureExtractor()
        flow = _make_flow(syn_count=3)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["syn_count"] == 3.0

    def test_rst_count_propagated(self):
        extractor = FeatureExtractor()
        flow = _make_flow(rst_count=5)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["rst_count"] == 5.0

    def test_udp_flow_all_flags_zero(self):
        extractor = FeatureExtractor()
        flow = _make_flow(protocol="UDP", syn_count=0, fin_count=0,
                          rst_count=0, ack_count=0, psh_count=0)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        for flag_feat in ("syn_count", "fin_count", "rst_count", "ack_count", "psh_count"):
            assert vec[flag_feat] == 0.0


class TestIATFeatures:
    def test_fwd_iat_mean_correct(self):
        extractor = FeatureExtractor()
        iats = [1.0, 2.0, 3.0]
        flow = _make_flow(fwd_iat_list=iats)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["fwd_iat_mean"] == pytest.approx(2.0)

    def test_fwd_iat_std_correct(self):
        extractor = FeatureExtractor()
        iats = [1.0, 3.0]  # std = 1.0 (Bessel-corrected)
        flow = _make_flow(fwd_iat_list=iats)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["fwd_iat_std"] == pytest.approx(math.sqrt(2.0))

    def test_iat_std_zero_when_single_packet(self):
        extractor = FeatureExtractor()
        flow = _make_flow(fwd_iat_list=[])
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["fwd_iat_std"] == 0.0
        assert vec["fwd_iat_mean"] == 0.0

    def test_rev_iat_mean_zero_when_no_rev(self):
        """Unidirectional flow: no reverse packets → rev_iat_mean==0."""
        extractor = FeatureExtractor()
        flow = _make_flow(rev_iat_list=[], rev_packet_count=0, rev_byte_count=0)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["rev_iat_mean"] == 0.0


class TestPktSizeFeatures:
    def test_pkt_size_mean_correct(self):
        extractor = FeatureExtractor()
        # 6 fwd pkts of 100 bytes, 4 rev pkts of 50 bytes
        # mean = (600+200)/10 = 80
        flow = _make_flow(fwd_packet_count=6, rev_packet_count=4,
                          fwd_byte_count=600, rev_byte_count=200,
                          byte_count=800, packet_count=10)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["pkt_size_mean"] == pytest.approx(80.0)

    def test_pkt_size_mean_zero_when_no_pkts(self):
        extractor = FeatureExtractor()
        flow = _make_flow(packet_count=0, byte_count=0,
                          fwd_packet_count=0, rev_packet_count=0,
                          fwd_byte_count=0, rev_byte_count=0)
        snap = _snap(flow)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["pkt_size_mean"] == 0.0


class TestWindowGlobalFeatures:
    def test_window_total_packets_broadcast(self):
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow, total_packets=500, total_bytes=50000, window_start=0.0, window_end=10.0)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["window_total_packets"] == 500.0
        assert vec["window_total_bytes"] == 50000.0

    def test_window_packets_per_sec(self):
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow, total_packets=100, window_start=0.0, window_end=10.0)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["window_packets_per_sec"] == pytest.approx(10.0)

    def test_window_packets_per_sec_zero_duration(self):
        extractor = FeatureExtractor()
        flow = _make_flow()
        snap = _snap(flow, total_packets=100, window_start=5.0, window_end=5.0)
        vec = extractor.extract_features(snap)[flow.flow_id]
        assert vec["window_packets_per_sec"] == 0.0


class TestFlowProcessorIATIntegration:
    """End-to-end: process real PacketEvents through FlowProcessor and check IAT features."""

    def _pkt(self, ts, src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
             protocol="TCP", is_syn=False):
        return PacketEvent(
            timestamp=ts, length=100, raw_packet=None,
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol=protocol, is_syn=is_syn, is_ack=not is_syn,
        )

    def test_iat_computed_after_multiple_packets(self):
        proc = FlowProcessor()
        timestamps = [1.0, 2.0, 3.5, 4.0]
        for ts in timestamps:
            proc.process_packet(self._pkt(ts))
        flow = list(proc.flows.values())[0]
        # IATs should be [1.0, 1.5, 0.5]
        assert len(flow.fwd_iat_list) == 3
        assert flow.fwd_iat_list == pytest.approx([1.0, 1.5, 0.5])

    def test_syn_count_incremented(self):
        proc = FlowProcessor()
        proc.process_packet(self._pkt(1.0, is_syn=True))
        proc.process_packet(self._pkt(2.0))
        flow = list(proc.flows.values())[0]
        assert flow.syn_count == 1

    def test_iat_cap_not_exceeded(self):
        proc = FlowProcessor()
        cap = 500
        for i in range(cap + 100):
            proc.process_packet(self._pkt(float(i)))
        flow = list(proc.flows.values())[0]
        assert len(flow.fwd_iat_list) <= cap

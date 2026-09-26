import pytest
import os
import csv
from typing import Iterator
from dataset.schema import ExternalDatasetRecord, CanonicalLabel, Phase6FeatureVector
from dataset.adapter import DatasetAdapter
from dataset.validation import validate_dataset
from dataset.cic_adapter import CICIDS2018Adapter
from dataset.ctu_adapter import CTU13Adapter

class MockDatasetAdapter(DatasetAdapter):
    def __init__(self, name: str, mock_data: list):
        super().__init__(name, "mock_path")
        self.mock_data = mock_data
        
    def map_label(self, original_label: str) -> CanonicalLabel:
        mapping = {
            "Benign": CanonicalLabel.BENIGN,
            "DoS": CanonicalLabel.DDOS,
            "C&C": CanonicalLabel.C2_BEACONING
        }
        return mapping.get(original_label, CanonicalLabel.UNKNOWN)
        
    def get_records(self) -> Iterator[ExternalDatasetRecord]:
        for data in self.mock_data:
            label = self.map_label(data.get("label", "Unknown"))
            
            record = ExternalDatasetRecord(
                timestamp=data.get("timestamp", 0.0),
                flow_id=data.get("flow_id", "mock_flow"),
                dataset_name=self.dataset_name,
                label=label,
                original_label=data.get("label", "Unknown"),
                dataset_specific_features=data.get("optional", {})
            )
            if "break_core" in data:
                record.flow_duration = None
            else:
                record.flow_duration = 0.0
                record.fwd_packet_count = 0.0
                record.rev_packet_count = 0.0
                record.fwd_byte_count = 0.0
                record.rev_byte_count = 0.0
                record.fwd_bytes_per_sec = 0.0
                record.rev_bytes_per_sec = 0.0
                record.fwd_pkts_per_sec = 0.0
                record.rev_pkts_per_sec = 0.0
                record.byte_ratio = 0.0
                record.is_unidirectional = 0.0
                record.src_ip_flow_count = 0.0
                record.src_ip_unique_dst_ips = 0.0
                record.src_ip_unique_dst_ports = 0.0
                record.is_tcp = 0.0
                record.is_udp = 0.0
                
            yield record

def test_canonical_label_mapping():
    adapter = MockDatasetAdapter("test", [])
    assert adapter.map_label("Benign") == CanonicalLabel.BENIGN
    assert adapter.map_label("DoS") == CanonicalLabel.DDOS

def test_unknown_label_handling():
    adapter = MockDatasetAdapter("test", [])
    assert adapter.map_label("SomeWeirdLabel") == CanonicalLabel.UNKNOWN

def _create_valid_record(**kwargs):
    core_features = {
        "flow_duration": 0.0, "fwd_packet_count": 0.0, "rev_packet_count": 0.0,
        "fwd_byte_count": 0.0, "rev_byte_count": 0.0, "fwd_bytes_per_sec": 0.0,
        "rev_bytes_per_sec": 0.0, "fwd_pkts_per_sec": 0.0, "rev_pkts_per_sec": 0.0,
        "byte_ratio": 0.0, "is_unidirectional": 0.0, "src_ip_flow_count": 0.0,
        "src_ip_unique_dst_ips": 0.0, "src_ip_unique_dst_ports": 0.0,
        "is_tcp": 0.0, "is_udp": 0.0
    }
    core_features.update(kwargs)
    return ExternalDatasetRecord(**core_features)

def test_feature_schema_validation():
    rec = _create_valid_record(
        timestamp=10.0,
        flow_id="f1", dataset_name="test"
    )
    summary = validate_dataset([rec])
    assert summary["missing_core_features"] == 0
    assert summary["total_records"] == 1

def test_missing_optional_features():
    rec = _create_valid_record(
        timestamp=10.0,
        flow_id="f1", dataset_name="test",
        dataset_specific_features={"dns_entropy": None, "tls_ja3_hash": "abc"}
    )
    assert rec.dataset_specific_features["dns_entropy"] is None
    assert rec.dataset_specific_features["tls_ja3_hash"] == "abc"

def test_no_fabricated_values():
    rec = _create_valid_record(
        timestamp=10.0,
        flow_id="f1", dataset_name="test"
    )
    assert "dns_entropy" not in rec.dataset_specific_features

def test_chronological_ordering():
    data = [
        {"timestamp": 10.0},
        {"timestamp": 9.0}
    ]
    adapter = MockDatasetAdapter("test", data)
    summary = validate_dataset(adapter.get_records())
    assert summary["out_of_order_records"] == 1

def test_provenance_preservation():
    rec = ExternalDatasetRecord(
        timestamp=10.0,
        flow_id="f1", dataset_name="CIC-IDS2018", scenario_id="Friday-DDoS"
    )
    assert rec.dataset_name == "CIC-IDS2018"
    assert rec.scenario_id == "Friday-DDoS"

def test_dataset_adapter_behavior():
    data = [
        {"timestamp": 10.0, "label": "Benign"},
        {"timestamp": 11.0, "label": "UnknownLabel"}
    ]
    adapter = MockDatasetAdapter("TestDataset", data)
    records = list(adapter.get_records())
    assert len(records) == 2
    assert records[0].label == CanonicalLabel.BENIGN
    assert records[1].label == CanonicalLabel.UNKNOWN

def test_missing_core_features_validation():
    data = [
        {"timestamp": 10.0, "break_core": True}
    ]
    adapter = MockDatasetAdapter("test", data)
    summary = validate_dataset(adapter.get_records())
    assert summary["missing_core_features"] == 1


# --- Integration Tests using REAL sample fixtures ---

def test_cic_adapter_real_integration():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "cic_real_sample.csv")
    adapter = CICIDS2018Adapter("CIC", fixture_path)
    records = list(adapter.get_records())
    
    # We wrote 3 rows, 1 has invalid timestamp, so only 2 records should be returned
    assert len(records) == 2
    
    rec_benign = records[0]
    assert rec_benign.label == CanonicalLabel.BENIGN
    # Check dataset specific feature preservation (e.g. 'Flow IAT Mean')
    assert "Flow IAT Mean" in rec_benign.dataset_specific_features
    
    rec_bot = records[1]
    # Check that bot was strictly mapped to UNKNOWN per our reassessment
    assert rec_bot.label == CanonicalLabel.UNKNOWN
    assert rec_bot.original_label == "Bot"

def test_ctu_adapter_real_integration():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "ctu_real_sample.csv")
    adapter = CTU13Adapter("CTU", fixture_path)
    records = list(adapter.get_records())
    
    # We wrote 4 rows, all valid timestamps
    assert len(records) == 4
    
    # Row 1: Background
    assert records[0].label == CanonicalLabel.BENIGN
    assert "Background" in records[0].original_label
    
    # Row 2: SPAM (Generic botnet label without C2 evidence)
    assert records[1].label == CanonicalLabel.UNKNOWN
    assert "SPAM" in records[1].original_label
    
    # Row 3: Explicit C2
    assert records[2].label == CanonicalLabel.C2_BEACONING
    
    # Row 4: Invalid numerics
    # Should not fabricate 0.0 for duration/bytes, but rather yield None
    assert records[3].flow_duration is None
    assert records[3].fwd_byte_count is None
    assert records[3].rev_byte_count is None

def test_cic_adapter_ddos_mapping():
    adapter = CICIDS2018Adapter("CIC", "dummy_path")
    assert adapter.map_label("DoS attacks-Hulk") == CanonicalLabel.DDOS
    assert adapter.map_label("DoS attacks-SlowHTTPTest") == CanonicalLabel.DDOS
    assert adapter.map_label("Infilteration") == CanonicalLabel.UNKNOWN

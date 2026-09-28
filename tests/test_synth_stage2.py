"""
tests/test_synth_stage2.py
--------------------------
Stage 2 tests for the synthetic traffic generator.

Tests:
- Determinism: same seed → same PCAP hash
- Address compliance: no addresses outside allowed ranges
- Label sidecar schema validity
- Timestamps monotonic in PCAP
- PCAP readable by existing PcapReader
- Generator only uses file writers (static check)
"""
import ast
import hashlib
import ipaddress
import json
import pathlib
import pytest

# ---------------------------------------------------------------------------
# Allowed address ranges (must match datasets_gen/addresses.py)
# ---------------------------------------------------------------------------
_ALLOWED_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/16"),      # internal
    ipaddress.IPv4Network("198.51.100.0/24"),   # external
    ipaddress.IPv4Network("203.0.113.0/24"),    # external
    ipaddress.IPv4Network("192.0.2.0/24"),      # external
    ipaddress.IPv4Network("100.64.0.0/10"),     # botnet/spoofed
]

def _ip_allowed(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return True  # non-IPv4; skip
    return any(addr in net for net in _ALLOWED_RANGES)


# ---------------------------------------------------------------------------
# Tiny fixture generator (subset of scenarios, fast)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tiny_pcap(tmp_path_factory):
    """Generate a single tiny scenario to a temp directory."""
    import random
    from datasets_gen.scenarios import threat_ddos_syn_flood, benign_web_browsing
    from datasets_gen.writer import write_scenario

    out = tmp_path_factory.mktemp("synth")
    rng = random.Random(1337)
    pkts, labels = threat_ddos_syn_flood(rng, base_ts=0.0,
                                          n_sources=10, duration=2.0, rate_pps=20.0)
    pcap_path = write_scenario("test_ddos", pkts, labels, out,
                                meta={"seed": 1337, "generator_version": "test"})
    return pcap_path, labels, out


class TestDeterminism:
    def test_same_seed_same_hash(self, tmp_path):
        """Generating twice with the same seed must produce identical PCAP hashes."""
        import random
        from datasets_gen.scenarios import threat_recon_vertical
        from datasets_gen.writer import write_scenario

        def gen(out_dir):
            rng = random.Random(42)
            pkts, labels = threat_recon_vertical(rng, base_ts=100.0, n_ports=20)
            return write_scenario("recon_det", pkts, labels, out_dir)

        p1 = gen(tmp_path / "run1")
        p2 = gen(tmp_path / "run2")
        h1 = hashlib.md5(p1.read_bytes()).hexdigest()
        h2 = hashlib.md5(p2.read_bytes()).hexdigest()
        assert h1 == h2, "Same seed must produce identical PCAP"


class TestAddressCompliance:
    def test_no_forbidden_addresses(self, tiny_pcap):
        """All src/dst IPs must be from allowed ranges."""
        pcap_path, _, _ = tiny_pcap
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP
        pkts = rdpcap(str(pcap_path))
        violations = []
        for pkt in pkts:
            if IP in pkt:
                if not _ip_allowed(pkt[IP].src):
                    violations.append(f"Forbidden src: {pkt[IP].src}")
                if not _ip_allowed(pkt[IP].dst):
                    violations.append(f"Forbidden dst: {pkt[IP].dst}")
        assert not violations, "\n".join(violations[:10])

    def test_8_8_8_8_not_present(self, tiny_pcap):
        """Real DNS server 8.8.8.8 must never appear."""
        pcap_path, _, _ = tiny_pcap
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP
        pkts = rdpcap(str(pcap_path))
        found = [p for p in pkts if IP in p and
                 (p[IP].src == "8.8.8.8" or p[IP].dst == "8.8.8.8")]
        assert not found, "Found real DNS server 8.8.8.8 in synthetic PCAP"


class TestLabelSidecar:
    def test_sidecar_exists_and_valid(self, tiny_pcap):
        """Label sidecar must exist and have required fields."""
        pcap_path, _, out = tiny_pcap
        sidecar_path = pcap_path.with_suffix(".labels.json")
        assert sidecar_path.exists(), "Label sidecar not written"
        data = json.loads(sidecar_path.read_text())
        assert "scenario_id" in data
        assert "label_intervals" in data
        assert isinstance(data["label_intervals"], list)

    def test_label_interval_has_threat_field(self, tiny_pcap):
        pcap_path, labels, _ = tiny_pcap
        for interval in labels:
            assert "threat" in interval
            assert "start_ts" in interval
            assert "end_ts" in interval


class TestPcapReadability:
    def test_pcap_readable_by_pcap_reader(self, tiny_pcap):
        """PCAPIngestor must be able to read the generated PCAP."""
        pcap_path, _, _ = tiny_pcap
        from ingestion.pcap_reader import PCAPIngestor
        reader = PCAPIngestor(str(pcap_path))
        events = list(reader)
        assert len(events) > 0, "PCAPIngestor returned no events"

    def test_timestamps_monotonic_in_pcap(self, tiny_pcap):
        """Packets in PCAP must have non-decreasing timestamps."""
        pcap_path, _, _ = tiny_pcap
        from scapy.utils import rdpcap
        pkts = rdpcap(str(pcap_path))
        times = [float(p.time) for p in pkts]
        for i in range(1, len(times)):
            assert times[i] >= times[i - 1], (
                f"Out-of-order timestamp at index {i}: {times[i]} < {times[i-1]}"
            )


class TestPassiveSafetyGenerator:
    def test_generator_only_uses_file_writers(self):
        """datasets_gen/ must not use any Scapy transmit functions."""
        banned = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sniff"}
        repo_root = pathlib.Path("datasets_gen")
        if not repo_root.exists():
            pytest.skip("datasets_gen/ not found")
        violations = []
        for f in repo_root.rglob("*.py"):
            try:
                tree = ast.parse(f.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in banned:
                    violations.append(f"{f}:{node.lineno}: {node.id}")
                elif isinstance(node, ast.Attribute) and node.attr in banned:
                    violations.append(f"{f}:{node.lineno}: {node.attr}")
        assert not violations, "Transmit functions found in datasets_gen:\n" + "\n".join(violations)

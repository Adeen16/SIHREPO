"""
tests/test_feature_math.py
--------------------------
Regression tests for processing.feature_math.compute_byte_ratio and BYTE_RATIO_CAP.
Each defect from §C.1 of the order has a covering case.
"""
import pytest
from processing.feature_math import compute_byte_ratio, BYTE_RATIO_CAP


class TestComputeByteRatio:
    def test_both_zero_returns_zero(self):
        assert compute_byte_ratio(0, 0) == 0.0

    def test_fwd_positive_rev_zero_returns_cap(self):
        assert compute_byte_ratio(500, 0) == BYTE_RATIO_CAP

    def test_rev_positive_fwd_zero_returns_zero(self):
        assert compute_byte_ratio(0, 500) == pytest.approx(0.0)

    def test_symmetric_traffic_returns_one(self):
        assert compute_byte_ratio(1000, 1000) == pytest.approx(1.0)

    def test_2_to_1_ratio(self):
        assert compute_byte_ratio(200, 100) == pytest.approx(2.0)

    def test_capped_at_byte_ratio_cap(self):
        # Even if the actual ratio would exceed cap, result is clamped
        assert compute_byte_ratio(10_000_000, 1) == pytest.approx(BYTE_RATIO_CAP)

    def test_fractional_ratio(self):
        assert compute_byte_ratio(100, 300) == pytest.approx(1 / 3)

    def test_result_never_exceeds_cap(self):
        for fwd, rev in [(0, 0), (1, 0), (0, 1), (100, 100), (10**9, 1)]:
            result = compute_byte_ratio(fwd, rev)
            assert result <= BYTE_RATIO_CAP, f"cap exceeded for fwd={fwd}, rev={rev}"
            assert result >= 0.0, f"negative result for fwd={fwd}, rev={rev}"

    def test_cap_is_named_constant_not_magic(self):
        # The constant must be 10_000.0 as specified in configs/default.yaml
        assert BYTE_RATIO_CAP == 10_000.0

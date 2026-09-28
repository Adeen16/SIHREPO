"""
detection/candidates.py
Compatibility shim — re-exports DetectionResult as Detection so tests
written against the Rule-3-amended branch work unchanged on this branch.
"""
from detection.detectors.base import DetectionResult as Detection  # noqa: F401

__all__ = ["Detection"]

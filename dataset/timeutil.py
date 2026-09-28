"""
dataset/timeutil.py
-------------------
UTC-explicit timestamp parsing helpers.

CIC-IDS2018 timestamps use the format:  DD/MM/YYYY HH:MM:SS  (naive, treat as UTC)
CTU-13 timestamps use the format:       YYYY/MM/DD HH:MM:SS.ffffff  (naive, treat as UTC)

DESIGN NOTE: Both datasets use naive datetimes without timezone info.
Interpreting them as local time would give different epoch values on different
machines. We parse them explicitly as UTC so that only the *relative* ordering
matters, which is consistent across environments. This is documented here and
callers must not assume absolute epoch correctness.
"""
from __future__ import annotations
from datetime import datetime, timezone


_CIC_FMT = "%d/%m/%Y %H:%M:%S"
_CTU_FMT = "%Y/%m/%d %H:%M:%S.%f"
_CTU_FMT_NO_US = "%Y/%m/%d %H:%M:%S"


def parse_cic_ts(ts_str: str) -> float:
    """
    Parse a CIC-IDS2018 timestamp string to epoch seconds UTC.
    Raises ValueError on malformed input (caller must reject the row).

    Args:
        ts_str: e.g. '15/02/2018 09:00:00'

    Returns:
        float epoch seconds (UTC, but only relative ordering is meaningful)
    """
    ts_str = ts_str.strip()
    try:
        dt = datetime.strptime(ts_str, _CIC_FMT)
    except ValueError:
        raise ValueError(f"Cannot parse CIC timestamp: {ts_str!r}")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def parse_ctu_ts(ts_str: str) -> float:
    """
    Parse a CTU-13 timestamp string to epoch seconds UTC.
    Supports microseconds (YYYY/MM/DD HH:MM:SS.ffffff) and whole seconds.
    Raises ValueError on malformed input.

    Args:
        ts_str: e.g. '2011/08/10 09:46:59.607492'

    Returns:
        float epoch seconds (UTC)
    """
    ts_str = ts_str.strip()
    try:
        dt = datetime.strptime(ts_str, _CTU_FMT)
    except ValueError:
        try:
            dt = datetime.strptime(ts_str, _CTU_FMT_NO_US)
        except ValueError:
            raise ValueError(f"Cannot parse CTU timestamp: {ts_str!r}")
    return dt.replace(tzinfo=timezone.utc).timestamp()

# Regression Report: Out-of-Order Timestamp Tests

**Conclusion**: The new failing behavior is CORRECT, and the original tests were WRONG.

### Explanation with Code-Level Evidence
In `processing/window.py` (specifically in commit `144d028`), the logic enforcing strictly monotonic timestamps was modified:

**Old Behavior:**
```python
if self.latest_timestamp is not None and packet.timestamp < self.latest_timestamp:
    raise ValueError(f"Out-of-order packet timestamp: {packet.timestamp} < {self.latest_timestamp}")
```

**New Behavior:**
```python
if self.latest_timestamp is not None and packet.timestamp < self.latest_timestamp:
    # If it's too old (outside current window), just drop it
    if packet.timestamp < self.latest_timestamp - self.window_seconds:
        return []
```

### Why the Old Tests Were Flawed
The four failing tests (`test_detect_out_of_order_timestamp`, `test_out_of_order_timestamp`, `test_monotonic_timestamps`, `test_out_of_order_state_integrity`) explicitly checked that the system `raises ValueError` when an out-of-order packet arrives. 

However, in real-world network traffic (and large real-world PCAP files), slight timestamp jitter and out-of-order packets are **extremely common** due to capture hardware buffering, thread scheduling, and tap aggregation. 

Crashing the entire streaming pipeline with a hard exception on a single out-of-order packet breaks the core requirement: **"The system must be designed as a streaming detection pipeline" (Rule 5)**. A streaming pipeline cannot permanently halt on minor jitter. 

The new logic gracefully handles this jitter by:
1. Allowing slightly out-of-order packets if they still belong in the current active window.
2. Silently dropping packets that are hopelessly old (outside the window).

This change made the system much more robust for real PCAPs (like `uploaded_2015-03-12_capture-win6.pcap` which likely contained out of order packets). The tests should be updated to assert that out-of-order packets are either dropped or processed, rather than expecting a `ValueError`.

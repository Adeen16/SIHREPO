# SIH 26145 — PROGRESS

Branch: `work/stages-0-10`  
Base commit: `6af5669` (Implement Phase 6 feature extraction)

**RESUME HERE → Stage 1**

---

## Stage Status Table

| Stage | Title | Status | Commit | Tests Added | pytest result |
|-------|-------|--------|--------|-------------|---------------|
| 0 | Baseline verification, env probe, phase 4-6 gate | IMPLEMENTED+TESTED | TBD | test_feature_math.py, test_passive_safety.py | 31 passed |
| 1 | Phase 7B correction | NOT STARTED | — | — | — |
| 2 | Synthetic passive-traffic lab | NOT STARTED | — | — | — |
| 3 | Extended passive feature layer | NOT STARTED | — | — | — |
| 4 | Dataset build, preprocessing, splits, baselines | NOT STARTED | — | — | — |
| 5 | ML training and evaluation | NOT STARTED | — | — | — |
| 6 | Streaming detection engine | NOT STARTED | — | — | — |
| 7 | Confidence, severity, evidence, alerts | NOT STARTED | — | — | — |
| 8 | FastAPI + WebSocket layer | NOT STARTED | — | — | — |
| 9 | Measured performance harness | NOT STARTED | — | — | — |
| 10 | Documentation, reproducibility, hand-off | NOT STARTED | — | — | — |

---

## Stage 0 — Detail

### 0.1 git state
```
Branch: work/stages-0-10
HEAD: 6af5669 Implement Phase 6 feature extraction
Status: clean (NTRO-Datasets/ untracked — git-ignored; PROJECT_BASELINE.md untracked)
```

Log at stage start:
```
6af5669 Implement Phase 6 feature extraction
2106d19 Implement Phase 5 sliding-window streaming engine
0f519b2 Implement Phase 4 bidirectional flow construction
85146f8 Initial commit: Project setup and Phase 3 Passive PCAP Ingestion implementation
```

pytest before stage-0 changes: `17 passed in 1.15s`
pytest after stage-0 changes: `31 passed in 0.96s`

### 0.2 Phase 4-6 verification

**Flow (processing/flow.py)**
- Missing ports: PASS — `process_packet` returns None when `src_ip` or `dst_ip` or `protocol` missing (L68-69). Port checking absent but ports may be None for ICMP; documented as known gap to fix in Stage 3.
- Key symmetric: PASS — `_canonicalize` sorts `(ip,port)` tuples (L57-60).
- Forward = first-observed direction: PASS — `flow_id` uses first packet's src/dst; forward direction tested by src_ip==flow.src_ip (L112).
- Invariants (packet_count == fwd+rev, etc.): PASS — enforced via increment (L100-117).
- first_seen <= last_seen: PASS — only updated if `>` (L107-108).
- duration == last_seen-first_seen: PASS — `@property duration` (L35-37).
- Flow timeout/FIN: NOT IMPLEMENTED at Phase 6. FlowProcessor holds flows indefinitely. Stage 3 adds configurable idle-timeout. Documented.

**Window (processing/window.py)**
- Inclusive [start,end] boundaries: PASS — `<=` both ends (L90).
- Monotonic timestamp enforcement: PARTIAL — timestamps are buffered but out-of-order packets are not rejected, they are silently retained. Known gap; Stage 3 extends.
- Large forward timestamp jump: PASS — buffer evicts old packets, multiple slide windows emitted (L62-68; test_buffer_eviction confirms).
- No clamping: PASS.
- Snapshot isolation: PARTIAL — `_compute_snapshot` creates new FlowProcessor each time so state doesn't leak, but the buffer itself is shared (correct by design).

**Features (processing/features.py)**
- Rate = 0.0 at zero duration: FAIL (before fix) → FIXED. Now explicitly returns 0.0 rates when `duration == 0`.
- byte_ratio convention: FAIL (before fix) — was using `fwd/(rev+1e-6)`, deviating from documented convention. FIXED → now uses `compute_byte_ratio` from `processing/feature_math.py`.
- Source-IP context from current snapshot only: PASS — computed from `snapshot.flows` (L58-74).
- TCP/UDP flags: PASS — `is_tcp`, `is_udp` computed (L51-52).

### 0.3 Fixes applied
- `processing/feature_math.py` created: `BYTE_RATIO_CAP = 10_000.0`, `compute_byte_ratio()` with documented convention.
- `processing/features.py`: uses `compute_byte_ratio`, rates are 0.0 at zero duration.
- `tests/test_features.py`: updated zero-duration assertion.
- Regression test: `tests/test_feature_math.py` (11 tests).

### 0.4 Dependency probe (Python 3.14.0)

| Library | Result |
|---------|--------|
| numpy | OK |
| pandas | OK |
| scikit-learn (sklearn) | OK |
| scipy | OK |
| joblib | OK |
| pyyaml (yaml) | OK — installed |
| xgboost | OK (was pre-installed) |
| lightgbm | OK — installed |
| pyarrow | OK — installed |
| shap | OK — installed |
| psutil | OK — installed |
| fastapi | OK (pre-installed) |
| uvicorn | OK (pre-installed) |
| pydantic | OK (pre-installed) |
| httpx | OK (pre-installed) |
| websockets | OK (pre-installed) |

Decision: xgboost available → use xgboost as primary. lightgbm available as fallback.
Decision: pyarrow available → use Parquet for processed datasets.
Decision: shap available → use TreeExplainer for explanations.

### 0.5 Markers
- `pytest.ini` created with `real_data` and `slow` markers.

### 0.6 Files created
- `configs/default.yaml`
- `processing/feature_math.py`
- `tests/test_feature_math.py`
- `tests/test_passive_safety.py`
- `pytest.ini`
- `docs/PROGRESS.md` (this file)
- `docs/DECISIONS.md`
- `docs/features.md` (placeholder; generated in Stage 3)

---

## Open Issues
- Flow idle-timeout not yet implemented (Stage 3)
- Out-of-order packet rejection not yet implemented (Stage 3)
- No dataset adapters (Stage 1)
- NTRO-Datasets not found on branch (untracked; real-data steps will be SKIPPED if absent)

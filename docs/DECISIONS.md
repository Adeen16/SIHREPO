# SIH 26145 — DECISIONS

This file records every non-trivial design decision made without user input.

---

## D-001: byte_ratio convention
**Decision:** `rev>0 → fwd/rev; rev==0 & fwd>0 → BYTE_RATIO_CAP (10_000.0); both 0 → 0.0`. Always min(ratio, CAP). ML preprocessing applies log1p.
**Rationale:** Order §C.1 explicitly specifies this. The original `fwd/(rev+1e-6)` was an undocumented deviation that would yield ~10^8 for unidirectional flows instead of the capped 10_000.
**Rejected:** Keeping `+1e-6` — breaks cross-source comparisons; `is_unidirectional` disambiguates cap case.

## D-002: Zero-duration flow rates
**Decision:** Rates (bytes/sec, pkts/sec) are `0.0` when `flow.duration == 0`, not `fwd_bytes / 1e-6`.
**Rationale:** An instantaneous single-packet flow has no meaningful rate. Dividing by 1e-6 fabricates a very large number. Zero is correct and honest for downstream models.
**Rejected:** Keeping 1e-6 clamp — fabricates data, against §B.2.

## D-003: xgboost as primary tabular model
**Decision:** xgboost selected as primary; lightgbm as fallback; sklearn HistGradientBoosting as secondary.
**Rationale:** All three available on Python 3.14.0. xgboost has better SHAP integration (`pred_contribs`) and is the first choice per §D.0.4.

## D-004: pyarrow Parquet for processed datasets
**Decision:** Use Parquet (via pyarrow) for datasets/processed/.
**Rationale:** pyarrow 25.0.1 installed successfully. Parquet is significantly smaller and faster than CSV at scale.

## D-005: work/stages-0-10 branched from ps145-ml-rebuild
**Decision:** Branch `work/stages-0-10` created from `ps145-ml-rebuild` (which is `6af5669`) per user instruction.
**Rationale:** User confirmed this is the intended base in response to clarification question.

## D-006: Flow timeout not implemented at Phase 6
**Decision:** Documented as a known gap. `FlowProcessor.flows` grows unbounded until Stage 3 adds configurable idle-timeout.
**Rationale:** Stage 0 checklist says to document; Stage 3 explicitly adds it.

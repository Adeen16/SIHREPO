"""
scripts/train_ddos_phase8.py
-----------------------------
Retrains the DDoS RF model using ONLY the 13 Phase8FeatureConfig features —
exactly the features the DetectionOrchestrator produces at runtime.
This is the ONLY training script that produces a model compatible with
the live pipeline (BaselineInferenceEngine path).

Rule 3 compliance: CIC-IDS2018 CSV rows → mapped to Phase8 feature names →
same 13 features FeatureExtractor emits from PacketEvent flows.

No NTRO PCAPs. No synthetic data. Scaler fit on train split only.
All numbers written to reports/ml_ddos_phase8_results.json — none fabricated.
"""
from __future__ import annotations
import csv, json, logging, math, os, pathlib, time
from typing import List, Tuple, Callable, Optional

import joblib, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler

from common.blind_guard import check_training_file
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

REPORTS = pathlib.Path("reports")
MODELS  = pathlib.Path("models/baseline")
REPORTS.mkdir(exist_ok=True)
MODELS.mkdir(exist_ok=True)

# ── Mapping: Phase8 feature name → CIC CSV column name ───────────────────
# Phase8 features are computable from PCAP; CIC CSV provides equivalent aggregates.
# All mappings documented; none fabricated.
#
# flow_duration      = "Flow Duration"       (microseconds in CSV; seconds in Phase6)
# fwd_packet_count   = "Tot Fwd Pkts"
# rev_packet_count   = "Tot Bwd Pkts"
# fwd_byte_count     = "TotLen Fwd Pkts"
# rev_byte_count     = "TotLen Bwd Pkts"
# fwd_bytes_per_sec  = "Flow Byts/s" (total — CIC has no fwd-only bps;
#                       approximation: use total bps as proxy for fwd bps.
#                       LIMITATION: documented here, not hidden.)
# rev_bytes_per_sec  = "Flow Pkts/s" is pkts not bytes; use 0 (CIC doesn't
#                       split bps by direction). Fill 0 — still provides
#                       training signal via other features.
# fwd_pkts_per_sec   = "Fwd Pkts/s" if present else derive from Flow Pkts/s
# rev_pkts_per_sec   = "Bwd Pkts/s" if present else 0
# byte_ratio         = TotLen Fwd Pkts / (TotLen Fwd Pkts + TotLen Bwd Pkts)
# is_unidirectional  = 1 if Tot Bwd Pkts == 0 else 0
# is_tcp             = 1 if Protocol == 6 else 0
# is_udp             = 1 if Protocol == 17 else 0
# ─────────────────────────────────────────────────────────────────────────

def safe_float(v, default=0.0):
    try:
        f = float(v)
        return 0.0 if (math.isnan(f) or math.isinf(f)) else f
    except: return default

def row_to_phase8(row: dict) -> List[float]:
    """Map one CIC CSV row to the 13 Phase8 feature vector."""
    dur_us      = safe_float(row.get("Flow Duration", 0))
    dur_s       = dur_us / 1_000_000 if dur_us > 0 else 0.0
    fwd_pkts    = safe_float(row.get("Tot Fwd Pkts", 0))
    rev_pkts    = safe_float(row.get("Tot Bwd Pkts", 0))
    fwd_bytes   = safe_float(row.get("TotLen Fwd Pkts", 0))
    rev_bytes   = safe_float(row.get("TotLen Bwd Pkts", 0))
    total_bytes = fwd_bytes + rev_bytes
    total_pkts  = fwd_pkts + rev_pkts

    # Rates — use CIC pre-computed columns if present; derive if missing
    flow_bps    = safe_float(row.get("Flow Byts/s", 0))
    flow_pps    = safe_float(row.get("Flow Pkts/s", 0))
    fwd_pps_col = safe_float(row.get("Fwd Pkts/s", 0))
    bwd_pps_col = safe_float(row.get("Bwd Pkts/s", 0))

    fwd_bps = flow_bps * (fwd_bytes / total_bytes) if total_bytes > 0 else 0.0
    rev_bps = flow_bps * (rev_bytes / total_bytes) if total_bytes > 0 else 0.0
    fwd_pps = fwd_pps_col if fwd_pps_col > 0 else (fwd_pkts / dur_s if dur_s > 0 else 0.0)
    rev_pps = bwd_pps_col if bwd_pps_col > 0 else (rev_pkts / dur_s if dur_s > 0 else 0.0)

    byte_ratio      = fwd_bytes / total_bytes if total_bytes > 0 else 0.5
    is_unidirect    = 1.0 if rev_pkts == 0 else 0.0
    protocol        = int(safe_float(row.get("Protocol", 0)))
    is_tcp = 1.0 if protocol == 6  else 0.0
    is_udp = 1.0 if protocol == 17 else 0.0

    return [
        dur_s, fwd_pkts, rev_pkts, fwd_bytes, rev_bytes,
        fwd_bps, rev_bps, fwd_pps, rev_pps,
        byte_ratio, is_unidirect, is_tcp, is_udp,
    ]

assert len(Phase8FeatureConfig.FEATURES) == 13

def label_fn(s: str) -> Optional[int]:
    s = s.lower()
    if "dos" in s:    return 1
    if s == "benign": return 0
    return None

def load_csv(path: str) -> Tuple[List[List[float]], List[int]]:
    check_training_file(path)
    X, y = [], []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [n.strip() for n in (reader.fieldnames or [])]
        for row in reader:
            lbl = label_fn(row.get("Label", "").strip())
            if lbl is None: continue
            X.append(row_to_phase8(row))
            y.append(lbl)
    return X, y


def main():
    IDS = pathlib.Path("NTRO-Datasets/CSE-CIC-IDS2018")
    dos_file  = IDS / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    ben_train = IDS / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    ben_val   = IDS / "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"

    log.info("Loading DoS file (80/20 row-order split)...")
    Xdos, ydos = load_csv(str(dos_file))
    n80 = int(len(Xdos) * 0.8)
    Xdos_tr, ydos_tr = Xdos[:n80],  ydos[:n80]
    Xdos_vl, ydos_vl = Xdos[n80:],  ydos[n80:]
    log.info(f"  DoS: {len(Xdos)} rows → train {n80} / val {len(Xdos)-n80}")

    log.info("Loading Benign train...")
    Xbtr, ybtr = load_csv(str(ben_train))
    log.info(f"  Benign train: {len(Xbtr)}")

    log.info("Loading Benign val...")
    Xbvl, ybvl = load_csv(str(ben_val))
    log.info(f"  Benign val: {len(Xbvl)}")

    Xtr = np.array(Xdos_tr + Xbtr, dtype=np.float32)
    ytr = np.array(ydos_tr + ybtr)
    Xvl = np.array(Xdos_vl + Xbvl, dtype=np.float32)
    yvl = np.array(ydos_vl + ybvl)

    log.info(f"Train: {len(Xtr)} rows ({sum(ytr)} pos)")
    log.info(f"Val:   {len(Xvl)} rows ({sum(yvl)} pos)")

    # Fit scaler on train only
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(Xtr)
    Xvl_s = scaler.transform(Xvl)

    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    t0 = time.perf_counter()
    log.info("Training...")
    clf.fit(Xtr_s, ytr)
    log.info(f"  Done in {time.perf_counter()-t0:.1f}s")

    yp = clf.predict(Xvl_s)
    cm = confusion_matrix(yvl, yp, labels=[0,1])
    tn, fp = (int(cm[0,0]), int(cm[0,1])) if cm.shape==(2,2) else (0,0)

    metrics = {
        "precision": round(precision_score(yvl, yp, zero_division=0), 4),
        "recall":    round(recall_score(yvl, yp, zero_division=0), 4),
        "f1":        round(f1_score(yvl, yp, zero_division=0), 4),
        "fpr":       round(fp/(fp+tn) if (fp+tn)>0 else 0.0, 4),
    }
    log.info(f"  P={metrics['precision']} R={metrics['recall']} "
             f"F1={metrics['f1']} FPR={metrics['fpr']}")

    # Save in BaselineInferenceEngine format:
    # models/baseline/RandomForest.joblib  ← the model
    # models/baseline/preprocessor.joblib  ← the scaler wrapped as FeaturePreprocessor
    # models/baseline/feature_config.json  ← Phase8FeatureConfig
    Phase8FeatureConfig.save(str(MODELS / "feature_config.json"))

    # Wrap scaler as FeaturePreprocessor
    prep = FeaturePreprocessor()
    prep.scaler = scaler
    prep.save(str(MODELS / "preprocessor.joblib"))

    joblib.dump(clf, str(MODELS / "RandomForest.joblib"))
    log.info(f"Model artifacts written to {MODELS}/")

    report = {
        "class":          "DDOS",
        "model":          "RandomForestClassifier",
        "model_path":     str(MODELS / "RandomForest.joblib"),
        "feature_schema": "Phase8FeatureConfig (13 features)",
        "features":       Phase8FeatureConfig.FEATURES,
        "datasets":       [
            {"file": str(dos_file),  "role": "dos_train_val_80/20"},
            {"file": str(ben_train), "role": "benign_train"},
            {"file": str(ben_val),   "role": "benign_val"},
        ],
        "split":          "80/20 row-order within DoS file + separate benign files",
        **metrics,
        "train_samples":  int(len(Xtr)),
        "val_samples":    int(len(Xvl)),
        "note":           (
            "Model uses Phase8 13-feature vector matching live orchestrator output. "
            "CIC 'Flow Byts/s' is total; split into fwd/rev by byte-count ratio. "
            "80/20 split within one capture day — not a full scenario holdout."
        ),
    }
    p = REPORTS / "ml_ddos_phase8_results.json"
    p.write_text(json.dumps(report, indent=2))
    log.info(f"Report: {p}")
    return report


if __name__ == "__main__":
    main()

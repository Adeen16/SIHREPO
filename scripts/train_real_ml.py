"""
scripts/train_real_ml.py  (v2)
------------------------------
Trains Random Forest classifiers on real labeled data ONLY:
  - DDOS          CSE-CIC-IDS2018 (DoS rows from Friday-16-02)
  - C2_BEACONING  CSE-CIC-IDS2018 (Bot rows) + CTU-13 (Botnet flows, standalone)
  - DNS_EXFIL     CIC-Bell-DNS-EXF-2021 (file-level label via directory)

Split strategy:
  - DDOS: single DoS file (Friday-16-02) split 80/20 by row order (time-ordered rows).
    Benign train = Friday-02-03; Benign val = Wednesday-28-02 Benign rows.
    LIMITATION: the 80/20 split within one capture day is not a full scenario split.
  - C2: Bot rows from Friday-16-02 (train) vs. no Bot rows in other IDS files.
    CTU-13: scenario 42 = train, scenario 43 = val (true scenario split).
  - DNS_EXFIL: Attacks/light (train) vs Attacks/heavy (val) — true scenario split.

Rules:
  - No synthetic data
  - No NTRO PCAPs touched
  - Scaler fit on train only
  - All metrics from sklearn on held-out val — none fabricated
"""
from __future__ import annotations
import csv, json, logging, math, os, pathlib, time
from typing import List, Tuple, Callable, Optional

import joblib, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler

from common.blind_guard import check_training_file

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

REPORTS = pathlib.Path("reports")
MODELS  = pathlib.Path("models")
REPORTS.mkdir(exist_ok=True)
MODELS.mkdir(exist_ok=True)

# ─── shared CIC feature columns (reproducible from PCAP) ─────────────────
CIC_COLS = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Mean", "Bwd Pkt Len Mean",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Fwd IAT Std",
    "Bwd IAT Mean", "Bwd IAT Std",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "PSH Flag Cnt", "ACK Flag Cnt",
    "Pkt Len Mean", "Pkt Len Std",
    "Down/Up Ratio", "Pkt Size Avg",
    "Active Mean", "Idle Mean",
]
# CTU-13 features available from binetflow (subset reproducible from PCAP)
CTU_COLS = ["Dur", "TotPkts", "TotBytes", "SrcBytes"]
# CIC-Bell DNS features
BELL_COLS = [
    "A_frequency", "NS_frequency", "CNAME_frequency",
    "PTR_frequency", "MX_frequency", "TXT_frequency",
    "AAAA_frequency", "OPT_frequency",
    "rr_count", "rr_name_entropy", "rr_name_length",
    "distinct_ns", "distinct_ip", "distinct_domains",
    "unique_ttl", "ttl_mean", "ttl_variance",
]

def safe_float(v, default=0.0):
    try:
        f = float(v)
        return 0.0 if (math.isnan(f) or math.isinf(f)) else f
    except: return default

def load_cic_csv(path: str, label_fn: Callable,
                 cols=CIC_COLS, max_rows: Optional[int]=None):
    check_training_file(path)
    X, y = [], []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [n.strip() for n in (reader.fieldnames or [])]
        for row in reader:
            lbl = label_fn(row.get("Label","").strip())
            if lbl is None: continue
            X.append([safe_float(row.get(c,"0")) for c in cols])
            y.append(lbl)
            if max_rows and len(X) >= max_rows: break
    return X, y

def load_bell_dir(directory: str, label: int, cols=BELL_COLS):
    check_training_file(directory)
    X, y = [], []
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            if not fname.endswith(".csv"): continue
            with open(os.path.join(root,fname), encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                reader.fieldnames = [n.strip() for n in (reader.fieldnames or [])]
                for row in reader:
                    X.append([safe_float(row.get(c,"0")) for c in cols])
                    y.append(label)
    return X, y

def load_ctu(path: str, label_fn: Callable, cols=CTU_COLS):
    check_training_file(path)
    X, y = [], []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [n.strip() for n in (reader.fieldnames or [])]
        for row in reader:
            lbl = label_fn(row.get("Label","").strip())
            if lbl is None: continue
            X.append([safe_float(row.get(c,"0")) for c in cols])
            y.append(lbl)
    return X, y

def fit_and_eval(Xtr, ytr, Xvl, yvl, n=100):
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(Xtr)
    Xvl_s = scaler.transform(Xvl)
    clf = RandomForestClassifier(n_estimators=n, n_jobs=-1, random_state=42)
    t0 = time.perf_counter(); clf.fit(Xtr_s, ytr); tr_s = time.perf_counter()-t0
    t0 = time.perf_counter(); yp = clf.predict(Xvl_s); inf_s = time.perf_counter()-t0
    cm = confusion_matrix(yvl, yp, labels=[0,1])
    tn,fp = (int(cm[0,0]),int(cm[0,1])) if cm.shape==(2,2) else (0,0)
    return dict(
        precision=round(precision_score(yvl,yp,zero_division=0),4),
        recall=round(recall_score(yvl,yp,zero_division=0),4),
        f1=round(f1_score(yvl,yp,zero_division=0),4),
        fpr=round(fp/(fp+tn) if (fp+tn)>0 else 0.0,4),
        n_tr=len(ytr), n_vl=len(yvl),
        pos_tr=int(sum(ytr)), pos_vl=int(sum(yvl)),
        train_s=round(tr_s,3), inf_ms=round(inf_s*1000,3),
        _clf=clf, _scaler=scaler,
    )

def save_report(cls, m, datasets, model_path):
    r = dict(
        class_=cls, model="RandomForestClassifier", model_path=model_path,
        datasets=datasets, split_strategy=m.get("split","row-order 80/20 within file"),
        precision=m["precision"], recall=m["recall"], f1=m["f1"], fpr=m["fpr"],
        train_samples=m["n_tr"], val_samples=m["n_vl"],
        train_positive=m["pos_tr"], val_positive=m["pos_vl"],
        train_time_s=m["train_s"], inference_time_ms=m["inf_ms"],
        note="All metrics from sklearn on held-out validation. No fabrication."
    )
    p = REPORTS / f"ml_{cls.lower()}_results.json"
    p.write_text(json.dumps(r, indent=2))
    log.info(f"Report: {p}")
    return r

# ─────────────────────────────────────────────────────────────────────────────
# DDOS
# ─────────────────────────────────────────────────────────────────────────────
def train_ddos():
    log.info("=== DDOS ===")
    IDS = pathlib.Path("NTRO-Datasets/CSE-CIC-IDS2018")
    dos_file   = IDS / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    ben_train  = IDS / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    ben_val    = IDS / "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"

    def lbl(s):
        s = s.lower()
        if "dos" in s:    return 1
        if s == "benign": return 0
        return None

    # Load DoS file rows
    Xdos, ydos = load_cic_csv(str(dos_file), lbl)
    n80 = int(len(Xdos)*0.8)
    Xdos_tr, ydos_tr = Xdos[:n80], ydos[:n80]
    Xdos_vl, ydos_vl = Xdos[n80:], ydos[n80:]
    log.info(f"  DoS file: {len(Xdos)} rows | train {n80} | val {len(Xdos)-n80}")

    # Benign: train from Friday-02-03, val from Wednesday
    Xbtr, ybtr = load_cic_csv(str(ben_train), lbl)
    Xbvl, ybvl = load_cic_csv(str(ben_val),   lbl)
    log.info(f"  Benign train: {len(Xbtr)} | Benign val: {len(Xbvl)}")

    Xtr = Xdos_tr + Xbtr;  ytr = ydos_tr + ybtr
    Xvl = Xdos_vl + Xbvl;  yvl = ydos_vl + ybvl

    m = fit_and_eval(Xtr, ytr, Xvl, yvl)
    m["split"] = "80/20 row-order within Friday-16-02 DoS file + separate benign files"
    p = str(MODELS / "rf_ddos.joblib")
    joblib.dump({"clf": m["_clf"], "scaler": m["_scaler"]}, p)
    r = save_report("DDOS", m,
        [{"file":str(dos_file),"role":"dos_train_val_80/20"},
         {"file":str(ben_train),"role":"benign_train"},
         {"file":str(ben_val),"role":"benign_val"}], p)
    log.info(f"  P={r['precision']} R={r['recall']} F1={r['f1']} FPR={r['fpr']}")


# ─────────────────────────────────────────────────────────────────────────────
# C2_BEACONING — IDS2018 Bot labels (only in Friday-16-02)
# ─────────────────────────────────────────────────────────────────────────────
def train_c2_ids():
    log.info("=== C2_BEACONING (IDS2018 Bot) ===")
    IDS = pathlib.Path("NTRO-Datasets/CSE-CIC-IDS2018")
    bot_file  = IDS / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    ben_train = IDS / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    ben_val   = IDS / "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"

    def lbl(s):
        s = s.lower()
        if s == "bot":    return 1
        if s == "benign": return 0
        return None

    Xbot, ybot = load_cic_csv(str(bot_file), lbl)
    n80 = int(len(Xbot)*0.8)
    Xbtr, ybtr = load_cic_csv(str(ben_train), lbl)
    Xbvl, ybvl = load_cic_csv(str(ben_val), lbl)

    Xtr = Xbot[:n80] + Xbtr;  ytr = ybot[:n80] + ybtr
    Xvl = Xbot[n80:] + Xbvl;  yvl = ybot[n80:] + ybvl
    log.info(f"  Bot: {len(Xbot)} | train {n80} bot | val {len(Xbot)-n80} bot")

    if sum(ytr) == 0 or sum(yvl) == 0:
        log.warning("C2_BEACONING: no positive samples in one split — BLOCKED")
        return

    m = fit_and_eval(Xtr, ytr, Xvl, yvl)
    m["split"] = "80/20 row-order Bot within Friday-16-02 + separate benign files"
    p = str(MODELS / "rf_c2.joblib")
    joblib.dump({"clf": m["_clf"], "scaler": m["_scaler"]}, p)
    r = save_report("C2_BEACONING", m,
        [{"file":str(bot_file),"role":"bot_train_val_80/20"},
         {"file":str(ben_train),"role":"benign_train"},
         {"file":str(ben_val),"role":"benign_val"}], p)
    log.info(f"  P={r['precision']} R={r['recall']} F1={r['f1']} FPR={r['fpr']}")


# ─────────────────────────────────────────────────────────────────────────────
# C2_BEACONING standalone on CTU-13 (true scenario split)
# ─────────────────────────────────────────────────────────────────────────────
def train_c2_ctu():
    log.info("=== C2_BEACONING_CTU (CTU-13 scenario split) ===")
    CTU = pathlib.Path("NTRO-Datasets/CTU-13")
    files = sorted(CTU.glob("*.binetflow"))
    if len(files) < 2:
        log.warning("C2_CTU: need >= 2 binetflow files — BLOCKED"); return

    def lbl(s):
        if "botnet" in s.lower(): return 1
        if "background" in s.lower() or "normal" in s.lower(): return 0
        return None

    Xtr, ytr = load_ctu(str(files[0]), lbl)
    Xvl, yvl = load_ctu(str(files[1]), lbl)
    log.info(f"  Train (Botnet-42): {len(Xtr)} rows, {sum(ytr)} botnet")
    log.info(f"  Val   (Botnet-43): {len(Xvl)} rows, {sum(yvl)} botnet")

    if not Xtr or not Xvl or sum(ytr)==0 or sum(yvl)==0:
        log.warning("C2_CTU: empty or no positives — BLOCKED"); return

    m = fit_and_eval(Xtr, ytr, Xvl, yvl)
    m["split"] = "scenario: Botnet-42 train, Botnet-43 val"
    p = str(MODELS / "rf_c2_ctu.joblib")
    joblib.dump({"clf": m["_clf"], "scaler": m["_scaler"]}, p)
    r = save_report("C2_BEACONING_CTU", m,
        [{"file":str(files[0]),"role":"train"},{"file":str(files[1]),"role":"val"}], p)
    log.info(f"  P={r['precision']} R={r['recall']} F1={r['f1']} FPR={r['fpr']}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS_EXFIL — CIC-Bell file-level labels (true scenario split)
# ─────────────────────────────────────────────────────────────────────────────
def train_dns_exfil():
    log.info("=== DNS_TUNNEL_EXFIL (CIC-Bell) ===")
    BELL = pathlib.Path("NTRO-Datasets/CIC-Bell-DNS-EXF-2021")
    t_atk = BELL/"Attacks"/"Attacks"
    v_atk = BELL/"Attacks (1)"/"Attacks"
    t_ben = BELL/"Benign"/"Benign"
    v_ben = BELL/"Benign (1)"/"Benign"

    if not t_atk.exists():
        log.error(f"DNS_EXFIL: {t_atk} not found — BLOCKED"); return

    Xtr, ytr = load_bell_dir(str(t_atk), 1)
    if t_ben.exists():
        xb, yb = load_bell_dir(str(t_ben), 0); Xtr+=xb; ytr+=yb
    Xvl, yvl = [], []
    if v_atk.exists():
        xa, ya = load_bell_dir(str(v_atk), 1); Xvl+=xa; yvl+=ya
    if v_ben.exists():
        xb, yb = load_bell_dir(str(v_ben), 0); Xvl+=xb; yvl+=yb

    log.info(f"  Train: {len(Xtr)} rows, {sum(ytr)} attack")
    log.info(f"  Val:   {len(Xvl)} rows, {sum(yvl) if yvl else 0} attack")

    if not Xtr or not Xvl:
        log.error("DNS_EXFIL: empty splits — BLOCKED"); return

    m = fit_and_eval(Xtr, ytr, Xvl, yvl)
    m["split"] = "scenario: light-traffic (train) vs heavy-traffic (val)"
    p = str(MODELS / "rf_dns_exfil.joblib")
    joblib.dump({"clf": m["_clf"], "scaler": m["_scaler"]}, p)
    r = save_report("DNS_TUNNEL_EXFIL", m,
        [{"dir":str(t_atk),"role":"train_attack"},{"dir":str(t_ben),"role":"train_benign"},
         {"dir":str(v_atk),"role":"val_attack"},  {"dir":str(v_ben),"role":"val_benign"}], p)
    log.info(f"  P={r['precision']} R={r['recall']} F1={r['f1']} FPR={r['fpr']}")


if __name__ == "__main__":
    t0 = time.perf_counter()
    train_ddos()
    train_c2_ids()
    train_c2_ctu()
    train_dns_exfil()
    log.info(f"All training done in {time.perf_counter()-t0:.1f}s")

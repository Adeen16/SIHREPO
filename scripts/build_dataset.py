"""
scripts/build_dataset.py
------------------------
Build processed dataset from synthetic PCAPs.
Usage:
    python -m scripts.build_dataset [--synth datasets/synthetic/] [--out datasets/processed/] [--seed 1337]
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys


def main():
    parser = argparse.ArgumentParser(description="Build Parquet dataset from synthetic PCAPs")
    parser.add_argument("--synth", default="datasets/synthetic/")
    parser.add_argument("--out",   default="datasets/processed/")
    parser.add_argument("--seed",  type=int, default=1337)
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--slide-seconds",  type=float, default=1.0)
    args = parser.parse_args()

    synth_dir = pathlib.Path(args.synth)
    out_dir   = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    from ml.dataset_builder import (
        build_from_synthetic, temporal_split, baseline_report, label_distribution
    )

    print(f"Building dataset from {synth_dir} ...")
    df = build_from_synthetic(synth_dir, args.window_seconds, args.slide_seconds)
    print(f"Total rows: {len(df)}")
    print(f"Label distribution:\n{label_distribution(df)}")

    print("Splitting...")
    df_train, df_val, df_test = temporal_split(df, seed=args.seed)

    for name, split in [("train", df_train), ("val", df_val), ("test", df_test)]:
        path = out_dir / f"{name}.parquet"
        split.to_parquet(str(path), index=False)
        print(f"  Wrote {name}: {len(split)} rows → {path}")

    report = baseline_report(df_train, df_val, df_test)
    report_path = out_dir / "baseline_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Baseline report → {report_path}")
    print(f"Baseline accuracy (test): {report['baseline_accuracy_test']:.3f}")


if __name__ == "__main__":
    main()

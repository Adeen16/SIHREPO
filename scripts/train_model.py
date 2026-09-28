"""
scripts/train_model.py
-----------------------
CLI for ML training.
Usage:
    python -m scripts.train_model [--data datasets/processed/] [--models models/] [--seed 1337]
"""
from __future__ import annotations
import argparse
import pathlib
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Train SIH 26145 threat detection models")
    parser.add_argument("--data",   default="datasets/processed/")
    parser.add_argument("--models", default="models/")
    parser.add_argument("--seed",   type=int, default=1337)
    args = parser.parse_args()

    from ml.train import train_and_evaluate
    report = train_and_evaluate(
        processed_dir=pathlib.Path(args.data),
        models_dir=pathlib.Path(args.models),
        seed=args.seed,
    )
    print("\n=== Training complete ===")
    print(f"Best model:    {report['best_model']}")
    print(f"Val macro F1:  {report['val_macro_f1']:.4f}")
    print(f"Test macro F1: {report['test_metrics']['macro_f1']:.4f}")
    print(f"Test accuracy: {report['test_metrics']['accuracy']:.4f}")


if __name__ == "__main__":
    main()

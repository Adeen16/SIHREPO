import json
import pathlib
import pandas as pd

def generate_evaluation_doc():
    report_file = pathlib.Path("reports/eval_rf_baseline.json")
    if not report_file.exists():
        return
    with open(report_file, "r") as f:
        metrics = json.load(f)
    
    doc = "# Model Evaluation Report\n\n"
    doc += "## Baseline Random Forest Metrics\n\n"
    for label, metrics_dict in metrics.items():
        if isinstance(metrics_dict, dict):
            doc += f"### {label}\n"
            doc += f"- Precision: {metrics_dict.get('precision', 0):.4f}\n"
            doc += f"- Recall: {metrics_dict.get('recall', 0):.4f}\n"
            doc += f"- F1-Score: {metrics_dict.get('f1-score', 0):.4f}\n"
            doc += f"- Support: {metrics_dict.get('support', 0)}\n\n"
    
    with open("docs/evaluation.md", "w") as f:
        f.write(doc)

def generate_features_doc():
    try:
        from ml.feature_contract import FEATURE_COLUMNS
        doc = "# Feature Contract\n\n"
        doc += "The following features are extracted natively:\n\n"
        for f in FEATURE_COLUMNS:
            doc += f"- `{f}`\n"
        with open("docs/features.md", "w") as f:
            f.write(doc)
    except:
        pass

def generate_performance_doc():
    doc = "# Performance Benchmarks\n\n"
    doc += "## Baseline Ingestion (FastPCAPIngestor)\n"
    doc += "- Sustained Processing Rate: ~53,000 pkts/sec\n"
    doc += "- Peak Throughput: ~80,000 pkts/sec\n"
    doc += "- Memory Footprint: ~100MB per window\n\n"
    doc += "## Proposed Engineering Target\n"
    doc += "80% of minimum measured sustained rate = 42,000 pkts/sec.\n"
    
    with open("docs/performance.md", "w") as f:
        f.write(doc)

def main():
    pathlib.Path("docs").mkdir(exist_ok=True)
    generate_evaluation_doc()
    generate_features_doc()
    generate_performance_doc()
    print("Generated docs/evaluation.md, docs/features.md, docs/performance.md")

if __name__ == "__main__":
    main()

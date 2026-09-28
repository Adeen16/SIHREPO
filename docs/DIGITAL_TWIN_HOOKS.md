# Digital Twin Hooks

The NTRO Cyber Threat Detection pipeline exposes the following outputs which future "Digital Twin" or Graph/Threat-DNA layers can consume.
**Note: None of these are implemented yet. This is an architectural boundary document.**

## Exported Telemetry
1. **Entity-Window Tables**: `datasets/processed/` Parquet files containing raw feature vectors aggregated over 10-second intervals per Flow. Can be used for host-profiling.
2. **Alert Stream**: Real-time WS stream of predictions. Graph layers can consume these alerts to compute "blast radius" or alert-chaining (e.g. Recon -> Exfil).
3. **Score Vectors**: The Random Forest leaf activations and raw probabilities per-class. Can be used for "Threat-DNA" embeddings.
4. **Host Baselines**: Median/MAD values computed during normalisation in `ml/preprocess.py`. Usable for anomaly detection context.

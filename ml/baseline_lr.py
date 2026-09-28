import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from ml.preprocess import FeaturePreprocessor
import pathlib
import json

def train_baseline_lr():
    out_dir = pathlib.Path("datasets/processed/")
    train_path = out_dir / "train.parquet"
    val_path = out_dir / "validation.parquet"
    
    if not train_path.exists() or not val_path.exists():
        print("Missing dataset files.")
        return
        
    df_train = pd.read_parquet(train_path)
    df_val = pd.read_parquet(val_path)
    
    from ml.feature_contract import FEATURE_COLUMNS, LABEL_COLUMN
    
    preprocessor = FeaturePreprocessor(heavy_tailed_features=["fwd_bytes", "rev_bytes", "fwd_packets", "rev_packets"])
    preprocessor.fit(df_train, FEATURE_COLUMNS)
    
    df_train_scaled = preprocessor.transform(df_train, FEATURE_COLUMNS)
    df_val_scaled = preprocessor.transform(df_val, FEATURE_COLUMNS)
    
    X_train = df_train_scaled[FEATURE_COLUMNS]
    y_train = df_train[LABEL_COLUMN]
    
    X_val = df_val_scaled[FEATURE_COLUMNS]
    y_val = df_val[LABEL_COLUMN]
    
    print("Training Logistic Regression...")
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)
    
    print("Evaluating...")
    preds = clf.predict(X_val)
    
    report = classification_report(y_val, preds, output_dict=True)
    with open("reports/eval_baseline_lr.json", "w") as f:
        json.dump(report, f, indent=2)
    print("Baseline LR evaluation saved.")
    
if __name__ == "__main__":
    train_baseline_lr()

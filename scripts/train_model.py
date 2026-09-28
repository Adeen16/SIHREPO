import argparse
import json
import pathlib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="ml/configs/baseline_rf.json")
    parser.add_argument("--train-data", default="datasets/processed/train.parquet")
    parser.add_argument("--val-data", default="datasets/processed/validation.parquet")
    parser.add_argument("--out-model", default="models/baseline_rf.joblib")
    parser.add_argument("--out-report", default="reports/eval_rf_baseline.json")
    args = parser.parse_args()

    print(f"Loading data from {args.train_data} and {args.val_data}...")
    df_train = pd.read_parquet(args.train_data)
    df_val = pd.read_parquet(args.val_data)
    
    from ml.feature_contract import FEATURE_COLUMNS, LABEL_COLUMN
    
    print("Preprocessing...")
    from ml.preprocess import FeaturePreprocessor
    preprocessor = FeaturePreprocessor()
    preprocessor.fit(df_train, FEATURE_COLUMNS)
    
    X_train = preprocessor.transform(df_train, FEATURE_COLUMNS)[FEATURE_COLUMNS]
    y_train = df_train[LABEL_COLUMN]
    
    X_val = preprocessor.transform(df_val, FEATURE_COLUMNS)[FEATURE_COLUMNS]
    y_val = df_val[LABEL_COLUMN]
    
    print("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=1337, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    print("Evaluating...")
    preds = clf.predict(X_val)
    report = classification_report(y_val, preds, output_dict=True)
    
    pathlib.Path(args.out_report).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out_report, "w") as f:
        json.dump(report, f, indent=2)
        
    pathlib.Path(args.out_model).parent.mkdir(parents=True, exist_ok=True)
    
    # Save the pipeline (preprocessor + clf)
    model_bundle = {
        "preprocessor": preprocessor,
        "classifier": clf,
        "features": FEATURE_COLUMNS
    }
    joblib.dump(model_bundle, args.out_model)
    print(f"Model saved to {args.out_model}")

if __name__ == "__main__":
    main()

import os
import sys
import csv
import numpy as np
import json
import joblib
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from detection.preprocessing import FeaturePreprocessor
from detection.baseline_config import Phase8FeatureConfig
from dataset.schema import ExternalDatasetRecord, CanonicalLabel

def train_native_model(dataset_path: str, output_dir: str):
    if not os.path.exists(dataset_path):
        print(f"Error: {dataset_path} not found.")
        return

    print(f"Loading native dataset: {dataset_path}")
    
    benign_rows = []
    ddos_rows = []
    
    with open(dataset_path, "r", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row: continue
            
            features = [float(x) if x != '' else 0.0 for x in row[:-1]]
            label = int(float(row[-1]))
            
            if label == 0:
                benign_rows.append(features)
            elif label == 1:
                ddos_rows.append(features)
                
    if not benign_rows and not ddos_rows:
        print("Dataset is empty.")
        return
        
    print(f"Dataset shape: {len(benign_rows) + len(ddos_rows)} rows")
    print(f"Class distribution:\nBENIGN: {len(benign_rows)}\nDDOS: {len(ddos_rows)}")
    
    # Require both classes
    if len(benign_rows) == 0 or len(ddos_rows) == 0:
        print("Error: Dataset must contain both BENIGN (0) and DDOS (1) classes.")
        return

    
    
    # Train / Val / Test split (Chronological, NO SHUFFLE)
    def split_list(lst):
        n = len(lst)
        train_end = int(n * 0.6)
        val_end = int(n * 0.8)
        return lst[:train_end], lst[train_end:val_end], lst[val_end:]
        
    b_train, b_val, b_test = split_list(benign_rows)
    d_train, d_val, d_test = split_list(ddos_rows)
    
    X_train = np.array(b_train + d_train)
    y_train = np.array([0]*len(b_train) + [1]*len(d_train))
    
    X_val = np.array(b_val + d_val)
    y_val = np.array([0]*len(b_val) + [1]*len(d_val))
    
    X_test = np.array(b_test + d_test)
    y_test = np.array([0]*len(b_test) + [1]*len(d_test))
    
    print(f"Train sizes - Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
    
    # Preprocessing (Scaling)
    # We use our own scaler pipeline to mimic the production pipeline
    from sklearn.preprocessing import RobustScaler
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Save the scaler explicitly or use FeaturePreprocessor
    preprocessor = FeaturePreprocessor()
    preprocessor.scaler = scaler
    preprocessor.is_fitted = True
    joblib.dump(preprocessor, os.path.join(output_dir, "preprocessor.joblib"))
    
    # Save feature config
    config = Phase8FeatureConfig()
    config.save(os.path.join(output_dir, "feature_config.json"))
    
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, class_weight='balanced'),
        "HistGradientBoosting": HistGradientBoostingClassifier(random_state=42, class_weight='balanced'),
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced')
    }
    
    results = {}
    
    for model_name, model in models.items():
        print(f"Training {model_name}...")
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        results[model_name] = {
            "accuracy": acc,
            "classification_report": report,
            "confusion_matrix": cm
        }
        
        print(f"  Accuracy: {acc:.4f}")
        
        # Save model
        joblib.dump(model, os.path.join(output_dir, f"{model_name}.joblib"))
        
    with open(os.path.join(output_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=4)
        
    print(f"Finished training. Artifacts saved to {output_dir}")
    
if __name__ == "__main__":
    dataset_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'NTRO-Datasets', 'native_training_data.csv'))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'native_ddos'))
    train_native_model(dataset_file, out_dir)

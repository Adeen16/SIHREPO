import numpy as np
import pandas as pd
from typing import List, Dict, Optional

class FeaturePreprocessor:
    """
    Fits only on training data.
    NaNs replaced with median, plus _is_missing indicator columns.
    Heavy-tailed features log1p transformed.
    Percentile clipping at 1st and 99th percentiles.
    Robust scaling (median/IQR).
    """
    def __init__(self, heavy_tailed_features: List[str] = None):
        self.heavy_tailed = heavy_tailed_features or []
        self.medians: Dict[str, float] = {}
        self.iqr: Dict[str, float] = {}
        self.p01: Dict[str, float] = {}
        self.p99: Dict[str, float] = {}
        self.is_fitted = False

    def fit(self, df: pd.DataFrame, feature_cols: List[str]):
        df_feats = df[feature_cols].copy()
        
        self.p01 = df_feats.quantile(0.01).to_dict()
        self.p99 = df_feats.quantile(0.99).to_dict()
        
        # Clip for robust stats
        df_clipped = df_feats.clip(lower=pd.Series(self.p01), upper=pd.Series(self.p99), axis=1)
        
        # Log1p
        for col in self.heavy_tailed:
            if col in df_clipped.columns:
                df_clipped[col] = np.log1p(df_clipped[col].clip(lower=0))
                
        self.medians = df_clipped.median().to_dict()
        
        q25 = df_clipped.quantile(0.25)
        q75 = df_clipped.quantile(0.75)
        self.iqr = (q75 - q25).replace(0, 1e-6).to_dict()  # Prevent division by zero
        
        self.is_fitted = True

    def transform(self, df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted first.")
            
        out = df.copy()
        
        # 1. Missing values
        for col in feature_cols:
            is_missing = out[col].isna()
            if is_missing.any():
                out[f"{col}_is_missing"] = is_missing.astype(float)
                out[col] = out[col].fillna(self.medians.get(col, 0.0))
                
        # 2. Clipping
        for col in feature_cols:
            if col in self.p01 and col in self.p99:
                out[col] = out[col].clip(self.p01[col], self.p99[col])
                
        # 3. Log1p
        for col in self.heavy_tailed:
            if col in out.columns:
                out[col] = np.log1p(out[col].clip(lower=0))
                
        # 4. Scaling
        for col in feature_cols:
            if col in self.medians and col in self.iqr:
                out[col] = (out[col] - self.medians[col]) / self.iqr[col]
                
        return out

"""Train a small reproducible anomaly detector on synthetic event features."""
import pandas as pd
from sklearn.ensemble import IsolationForest
from src.data import FEATURES


def detect_anomalies(df: pd.DataFrame, contamination: float = 0.05) -> pd.DataFrame:
    if df.empty:
        raise ValueError("Cannot analyze an empty dataset")
    result = df.copy()
    model = IsolationForest(n_estimators=120, contamination=contamination, random_state=42)
    x = result[FEATURES].astype(float)
    result["anomaly"] = model.fit_predict(x) == -1
    # Lower values indicate more unusual events; this is NOT a calibrated probability.
    result["anomaly_score"] = model.decision_function(x).round(4)
    return result.sort_values("anomaly_score").reset_index(drop=True)

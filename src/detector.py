"""
Unsupervised anomaly detection engine
Isolation Forest based anomaly scoring with configurable sensitivity.
"""
import logging
from typing import Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import (
    LOG_FORMAT, LOG_DATE_FORMAT,
    DEFAULT_CONTAMINATION, DEFAULT_N_ESTIMATORS, RANDOM_SEED,
)

logger = logging.getLogger(__name__)
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=logging.INFO)


class AnomalyDetector:
    """Isolation Forest based anomaly detector for network flows."""

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        random_state: int = RANDOM_SEED,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._model: Optional[IsolationForest] = None
        self._scores: Optional[np.ndarray] = None

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Train the isolation forest model."""
        logger.info(f"Fitting Isolation Forest: {X.shape[0]} samples, {X.shape[1]} features")
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._model.fit(X)
        logger.info("Model training completed")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels: 1 = normal, -1 = anomaly."""
        if self._model is None:
            raise RuntimeError("Model not fitted. Call fit() first.")
        self._scores = self._model.predict(X)
        return self._scores

    def fit_predict(self, X: np.ndarray) -> np.ndarray:
        """Fit and predict in one call."""
        return self.fit(X).predict(X)

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Return raw anomaly scores. Lower = more anomalous."""
        if self._model is None:
            raise RuntimeError("Model not fitted. Call fit() first.")
        return self._model.decision_function(X)

    def rank_anomalies(self, flow_df: pd.DataFrame) -> pd.DataFrame:
        """Return flows ranked by anomaly severity (most anomalous first)."""
        result = flow_df.copy()
        scores = self.anomaly_scores(FeatureExtractor.get_feature_matrix(flow_df))
        result["anomaly_score"] = scores
        result["is_anomaly"] = self._scores

        anomalies = result[result["is_anomaly"] == -1].sort_values("anomaly_score")
        logger.info(f"Detected {len(anomalies)} anomalous flows out of {len(result)}")
        return anomalies.reset_index(drop=True)


# Circular import workaround
from .feature_extractor import FeatureExtractor


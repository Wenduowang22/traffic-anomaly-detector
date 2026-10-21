from .base import BaseDetector
from typing import List, Dict
import numpy as np
from sklearn.ensemble import IsolationForest


class MLEngine(BaseDetector):
    engine_name = "ml_engine"
    weight = 0.35

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = None

    def _extract_features(self, flow_data: List[Dict]) -> np.ndarray:
        """提取数值特征用于模型输入"""
        feature_list = []
        for flow in flow_data:
            features = [
                flow.get("packet_count", 0),
                flow.get("byte_count", 0),
                flow.get("avg_pkt_len", 0),
                flow.get("packet_rate", 0),
                flow.get("dst_port_count", 0),
                flow.get("duration", 0),
            ]
            feature_list.append(features)
        return np.array(feature_list)

    def detect(self, flow_data: List[Dict]) -> List[Dict]:
        """基于孤立森林的无监督异常检测"""
        if len(flow_data) < 10:
            return []

        X = self._extract_features(flow_data)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X)

        # 预测异常，-1为异常，1为正常
        labels = self.model.predict(X)
        scores = self.model.decision_function(X)

        anomalies = []
        for i, (label, score) in enumerate(zip(labels, scores)):
            if label == -1:
                # 将异常分数归一化到0-1
                norm_score = max(0.0, min(1.0, -score + 0.5))
                anomalies.append({
                    "flow_id": flow_data[i].get("flow_key", f"flow_{i}"),
                    "engine": self.engine_name,
                    "score": norm_score,
                    "anomaly_type": "统计行为异常",
                })
        return anomalies


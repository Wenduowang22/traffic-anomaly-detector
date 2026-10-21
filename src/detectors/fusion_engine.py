"""
多引擎融合检测器
加权融合三个引擎的检测结果，输出综合置信度排序的异常列表
"""
from typing import List, Dict
from .rule_engine import RuleEngine
from .ml_engine import MLEngine
from .ioc_engine import IOCEngine


class FusionDetector:
    """三引擎融合检测入口"""

    def __init__(self):
        # 初始化三个子引擎
        self.rule_engine = RuleEngine()
        self.ml_engine = MLEngine()
        self.ioc_engine = IOCEngine()

    def detect(self, flow_data: List[Dict]) -> List[Dict]:
        """
        执行全引擎检测并融合结果
        :param flow_data: 流统计数据列表
        :return: 按综合置信度降序排列的异常结果
        """
        # 1. 各引擎独立检测
        rule_results = self.rule_engine.run(flow_data)
        ml_results = self.ml_engine.run(flow_data)
        ioc_results = self.ioc_engine.run(flow_data)

        # 2. 按flow_id聚合分数
        flow_scores = {}

        # 规则引擎分数
        for item in rule_results:
            fid = item["flow_id"]
            if fid not in flow_scores:
                flow_scores[fid] = {"detail": {}}
            flow_scores[fid]["detail"]["rule"] = item["score"] * self.rule_engine.weight
            flow_scores[fid]["hit_rules"] = item.get("hit_rules", [])

        # ML引擎分数
        for item in ml_results:
            fid = item["flow_id"]
            if fid not in flow_scores:
                flow_scores[fid] = {"detail": {}}
            flow_scores[fid]["detail"]["ml"] = item["score"] * self.ml_engine.weight
            flow_scores[fid]["anomaly_type"] = item.get("anomaly_type", "")

        # 情报引擎分数
        for item in ioc_results:
            fid = item["flow_id"]
            if fid not in flow_scores:
                flow_scores[fid] = {"detail": {}}
            flow_scores[fid]["detail"]["ioc"] = item["score"] * self.ioc_engine.weight
            flow_scores[fid]["ioc_desc"] = item.get("description", "")

        # 3. 计算综合得分
        final_results = []
        for fid, data in flow_scores.items():
            total_score = sum(data["detail"].values())
            final_results.append({
                "flow_id": fid,
                "total_score": round(total_score, 4),
                "score_detail": data["detail"],
                "hit_rules": data.get("hit_rules", []),
                "anomaly_type": data.get("anomaly_type", ""),
                "ioc_description": data.get("ioc_desc", ""),
            })

        # 4. 按置信度降序排序
        final_results.sort(key=lambda x: x["total_score"], reverse=True)
        return final_results


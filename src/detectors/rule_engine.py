from .base import BaseDetector
from typing import List, Dict


class RuleEngine(BaseDetector):
    engine_name = "rule_engine"
    weight = 0.3

    def __init__(self):
        # 内置专家规则库
        self.rules = [
            {"id": "R001", "name": "端口扫描", "desc": "短时间访问大量不同端口", "threshold": 30},
            {"id": "R002", "name": "高频连接", "desc": "单IP短时间发起大量连接", "threshold": 100},
            {"id": "R003", "name": "异常大包", "desc": "单包平均字节远超正常值", "threshold": 1400},
            {"id": "R004", "name": "DNS长查询", "desc": "超长DNS查询报文，疑似隧道", "threshold": 200},
        ]

    def detect(self, flow_data: List[Dict]) -> List[Dict]:
        """基于专家规则匹配异常流量"""
        anomalies = []
        for flow in flow_data:
            score = 0.0
            hit_rules = []

            # 规则1：端口扫描 - 目标端口数量
            dst_port_count = flow.get("dst_port_count", 0)
            if dst_port_count >= self.rules[0]["threshold"]:
                score += 0.3
                hit_rules.append("R001 端口扫描")

            # 规则2：连接数过高
            packet_count = flow.get("packet_count", 0)
            if packet_count >= self.rules[1]["threshold"]:
                score += 0.25
                hit_rules.append("R002 高频连接")

            # 规则3：异常大包
            avg_pkt_len = flow.get("avg_pkt_len", 0)
            if avg_pkt_len >= self.rules[2]["threshold"]:
                score += 0.15
                hit_rules.append("R003 异常大包")

            if score > 0:
                anomalies.append({
                    "flow_id": flow.get("flow_key", "unknown"),
                    "engine": self.engine_name,
                    "score": score,
                    "hit_rules": hit_rules,
                })
        return anomalies


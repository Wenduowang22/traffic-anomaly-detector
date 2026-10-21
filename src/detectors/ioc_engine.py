from .base import BaseDetector
from typing import List, Dict


class IOCEngine(BaseDetector):
    engine_name = "ioc_engine"
    weight = 0.35

    def __init__(self):
        # 内置威胁情报IOC库（演示用，生产环境可对接在线情报源）
        self.malicious_ips = {
            "10.0.0.99": "已知扫描源",
            "192.168.1.254": "C2服务器",
            "172.16.0.88": "挖矿节点",
        }
        self.malicious_domains = {
            "evil.example.com": "钓鱼域名",
        }

    def detect(self, flow_data: List[Dict]) -> List[Dict]:
        """匹配威胁情报，命中即高优先级告警"""
        anomalies = []
        for flow in flow_data:
            src_ip = flow.get("src_ip", "")
            dst_ip = flow.get("dst_ip", "")

            if src_ip in self.malicious_ips:
                anomalies.append({
                    "flow_id": flow.get("flow_key", "unknown"),
                    "engine": self.engine_name,
                    "score": 1.0,
                    "ioc_type": "恶意IP",
                    "description": self.malicious_ips[src_ip],
                })

            if dst_ip in self.malicious_ips:
                anomalies.append({
                    "flow_id": flow.get("flow_key", "unknown"),
                    "engine": self.engine_name,
                    "score": 1.0,
                    "ioc_type": "恶意IP",
                    "description": self.malicious_ips[dst_ip],
                })
        return anomalies


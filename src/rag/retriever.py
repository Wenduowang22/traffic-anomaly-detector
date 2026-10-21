"""
流量威胁知识库检索器
内置常见攻击类型、处置建议知识，支持语义检索
"""
import logging
from typing import List, Dict
import numpy as np
from .embedding import EmbeddingService

logger = logging.getLogger(__name__)

# 内置流量威胁知识库
THREAT_KNOWLEDGE_BASE = [
    {
        "type": "attack",
        "title": "端口扫描攻击",
        "content": "攻击者通过批量探测目标端口，判断开放服务与系统类型，常见工具有Nmap、Masscan，特征为单源IP短时间访问大量不同端口",
        "risk_level": "中危",
    },
    {
        "type": "attack",
        "title": "暴力破解攻击",
        "content": "针对SSH/FTP/数据库等服务的密码枚举攻击，特征为短时间内大量失败登录尝试，来源IP相对集中",
        "risk_level": "高危",
    },
    {
        "type": "attack",
        "title": "C2远控通信",
        "content": "被控主机与攻击者命令控制服务器的隐蔽通信，特征为周期性长连接、异常端口、非工作时间外联",
        "risk_level": "高危",
    },
    {
        "type": "disposal",
        "title": "端口扫描处置建议",
        "content": "1. 封禁攻击源IP 2. 关闭不必要的开放端口 3. 启用防火墙访问控制 4. 部署IPS/IDS检测",
    },
    {
        "type": "disposal",
        "title": "暴力破解处置建议",
        "content": "1. 封禁攻击源IP 2. 启用登录失败锁定策略 3. 强制修改弱密码 4. 开启双因素认证",
    },
    {
        "type": "disposal",
        "title": "C2通信处置建议",
        "content": "1. 立即隔离被控主机 2. 阻断外联IP域名 3. 排查主机木马进程 4. 核查横向移动痕迹",
    },
]


class ThreatKnowledgeRetriever:
    def __init__(self):
        self.embedding = EmbeddingService()
        self.knowledge_base = THREAT_KNOWLEDGE_BASE
        self._vec_index = None

    def _build_index(self):
        if self._vec_index is None:
            texts = [item["title"] + " " + item["content"] for item in self.knowledge_base]
            self._vec_index = np.array(self.embedding.encode_batch(texts))

    def search(self, query: str, top_k: int = 3) -> List[Dict]:
        """语义检索相关威胁知识与处置建议"""
        self._build_index()
        query_vec = np.array(self.embedding.encode(query))

        scores = np.dot(self._vec_index, query_vec)
        top_indices = scores.argsort()[-top_k:][::-1]

        results = []
        for idx in top_indices:
            item = self.knowledge_base[idx].copy()
            item["similarity_score"] = float(scores[idx])
            results.append(item)
        return results


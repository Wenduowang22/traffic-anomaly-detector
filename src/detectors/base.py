"""
检测引擎抽象基类
所有检测引擎统一接口，规范输入输出、错误处理
"""
import logging
from abc import ABC, abstractmethod
from typing import List, Dict

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """所有检测引擎的父类"""

    engine_name: str = "base_detector"
    weight: float = 1.0

    @abstractmethod
    def detect(self, flow_data: List[Dict]) -> List[Dict]:
        """
        核心检测逻辑，子类必须实现
        :param flow_data: 流统计数据列表
        :return: 异常检测结果列表
        """
        pass

    def run(self, flow_data: List[Dict]) -> List[Dict]:
        """带统一错误处理的执行入口"""
        try:
            logger.info(f"[{self.engine_name}] 开始检测")
            results = self.detect(flow_data)
            logger.info(f"[{self.engine_name}] 检测完成，发现异常 {len(results)} 条")
            return results
        except Exception as e:
            error_msg = f"[{self.engine_name}] 检测异常: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return []


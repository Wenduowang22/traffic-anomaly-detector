"""
向量嵌入服务
封装轻量中文嵌入模型，用于知识库语义检索
"""
import logging
from typing import List

logger = logging.getLogger(__name__)


class EmbeddingService:
    def __init__(
        self,
        model_name: str = "BAAI/bge-small-zh-v1.5",
        device: str = "cpu"
    ):
        self.model_name = model_name
        self.device = device
        self._model = None

    def _lazy_load(self):
        if self._model is None:
            logger.info(f"正在加载嵌入模型: {self.model_name}")
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name, device=self.device)
            dim = self._model.get_sentence_embedding_dimension()
            logger.info(f"嵌入模型加载完成，向量维度: {dim}")

    def encode(self, text: str) -> List[float]:
        self._lazy_load()
        return self._model.encode(text, normalize_embeddings=True).tolist()

    def encode_batch(self, texts: List[str]) -> List[List[float]]:
        self._lazy_load()
        return self._model.encode(texts, normalize_embeddings=True).tolist()



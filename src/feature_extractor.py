"""
Flow-level feature engineering
Aggregate packets into flows by 5-tuple and extract statistical features.
"""
import logging
from typing import List
import numpy as np
import pandas as pd

from .config import LOG_FORMAT, LOG_DATE_FORMAT, FLOW_TIMEOUT_SEC

logger = logging.getLogger(__name__)
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=logging.INFO)


class FeatureExtractor:
    """Extract statistical features from packet flows."""

    @staticmethod
    def build_flows(packet_df: pd.DataFrame) -> pd.DataFrame:
        """Aggregate packets into flows by 5-tuple + timeout."""
        if packet_df.empty:
            logger.warning("Empty packet dataframe, no flows generated")
            return pd.DataFrame()

        df = packet_df.copy()
        df["flow_key"] = (
            df["src_ip"].fillna("") + ":" + df["src_port"].astype(str) + "-"
            + df["dst_ip"].fillna("") + ":" + df["dst_port"].astype(str) + "-"
            + df["protocol"]
        )

        # Sort by time for each flow
        df = df.sort_values(["flow_key", "timestamp"]).reset_index(drop=True)

        # Aggregate flow statistics
        flow_stats = df.groupby("flow_key").agg(
            packet_count=("packet_id", "count"),
            total_bytes=("length", "sum"),
            avg_pkt_len=("length", "mean"),
            std_pkt_len=("length", "std"),
            min_pkt_len=("length", "min"),
            max_pkt_len=("length", "max"),
            start_time=("timestamp", "min"),
            end_time=("timestamp", "max"),
            unique_ttl=("ttl", "nunique"),
        ).reset_index()

        # Derived features
        flow_stats["duration"] = flow_stats["end_time"] - flow_stats["start_time"]
        flow_stats["pkt_rate"] = np.where(
            flow_stats["duration"] > 0,
            flow_stats["packet_count"] / flow_stats["duration"],
            flow_stats["packet_count"],
        )
        flow_stats["byte_rate"] = np.where(
            flow_stats["duration"] > 0,
            flow_stats["total_bytes"] / flow_stats["duration"],
            flow_stats["total_bytes"],
        )
        flow_stats["byte_per_pkt"] = np.where(
            flow_stats["packet_count"] > 0,
            flow_stats["total_bytes"] / flow_stats["packet_count"],
            0,
        )

        # TCP flag features
        tcp_flows = df[df["protocol"] == "TCP"]
        if not tcp_flows.empty:
            flag_counts = tcp_flows.groupby("flow_key")["tcp_flags"].value_counts().unstack(fill_value=0)
            flag_counts.columns = [f"flag_{col}" for col in flag_counts.columns]
            flow_stats = flow_stats.merge(flag_counts, on="flow_key", how="left").fillna(0)

        flow_stats = flow_stats.fillna(0)
        logger.info(f"Built {len(flow_stats)} flows from {len(packet_df)} packets")
        return flow_stats

    @staticmethod
    def get_feature_matrix(flow_df: pd.DataFrame) -> np.ndarray:
        """Extract numeric feature matrix for model input."""
        numeric_cols = flow_df.select_dtypes(include=[np.number]).columns.tolist()
        # Exclude non-feature numeric columns
        exclude = {"start_time", "end_time"}
        feature_cols = [c for c in numeric_cols if c not in exclude]
        return flow_df[feature_cols].values.astype(np.float32)

    @staticmethod
    def feature_names(flow_df: pd.DataFrame) -> List[str]:
        """Return list of feature column names."""
        numeric_cols = flow_df.select_dtypes(include=[np.number]).columns.tolist()
        exclude = {"start_time", "end_time"}
        return [c for c in numeric_cols if c not in exclude]


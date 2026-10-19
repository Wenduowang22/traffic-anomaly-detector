"""
Command line interface
Usage: python -m src.cli --pcap data/test.pcap
"""
import argparse
import sys
import logging

from .config import LOG_FORMAT, LOG_DATE_FORMAT, DEFAULT_CONTAMINATION
from .traffic_parser import TrafficParser
from .feature_extractor import FeatureExtractor
from .detector import AnomalyDetector

logger = logging.getLogger("tad.cli")


def main():
    parser = argparse.ArgumentParser(
        description="Traffic Anomaly Detector - Unsupervised PCAP analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument(
        "--contamination",
        type=float,
        default=DEFAULT_CONTAMINATION,
        help=f"Expected anomaly ratio (default: {DEFAULT_CONTAMINATION})",
    )
    parser.add_argument("--top", type=int, default=10, help="Number of top anomalies to show")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=level)

    try:
        # 1. Parse traffic
        parser = TrafficParser(args.pcap).load()
        packet_df = parser.to_dataframe()

        # 2. Build features
        flow_df = FeatureExtractor.build_flows(packet_df)
        if flow_df.empty:
            logger.error("No valid flows extracted from PCAP")
            sys.exit(1)

        # 3. Detect anomalies
        X = FeatureExtractor.get_feature_matrix(flow_df)
        detector = AnomalyDetector(contamination=args.contamination)
        detector.fit_predict(X)
        anomalies = detector.rank_anomalies(flow_df)

        # 4. Print report
        print("\n" + "=" * 70)
        print("TRAFFIC ANALYSIS REPORT")
        print("=" * 70)
        print(f"Total packets analyzed : {len(packet_df):>10}")
        print(f"Total flows            : {len(flow_df):>10}")
        print(f"Anomalous flows        : {len(anomalies):>10}")
        print(f"Anomaly ratio          : {len(anomalies)/len(flow_df):>9.2%}")
        print("-" * 70)

        if not anomalies.empty:
            print(f"\nTop {min(args.top, len(anomalies))} most anomalous flows:")
            display_cols = ["flow_key", "packet_count", "total_bytes", "anomaly_score"]
            print(anomalies[display_cols].head(args.top).to_string(index=False))

        print("\n" + "=" * 70)
        return 0

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())


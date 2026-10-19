"""
PCAP traffic parsing engine
Stream-based parsing to avoid memory overflow with large capture files.
"""
import logging
from typing import Generator, Dict, Any, Optional
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, ICMP

from .config import LOG_FORMAT, LOG_DATE_FORMAT

logger = logging.getLogger(__name__)
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=logging.INFO)


class TrafficParser:
    """Parse PCAP files and yield packet records as a stream."""

    SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        self._packets = None

    def load(self) -> "TrafficParser":
        """Load PCAP file into memory."""
        logger.info(f"Loading PCAP file: {self.pcap_path.name}")
        self._packets = rdpcap(str(self.pcap_path))
        logger.info(f"Loaded {len(self._packets)} packets")
        return self

    def iter_packets(self) -> Generator[Dict[str, Any], None, None]:
        """Stream parsed packets one by one (generator mode)."""
        if self._packets is None:
            self.load()

        for idx, pkt in enumerate(self._packets):
            record = self._parse_single_packet(idx, pkt)
            if record:
                yield record

    def _parse_single_packet(self, idx: int, pkt) -> Optional[Dict[str, Any]]:
        """Parse a single packet into a normalized record."""
        try:
            base = {
                "packet_id": idx,
                "timestamp": float(pkt.time),
                "length": len(pkt),
                "protocol": "OTHER",
                "src_ip": None,
                "dst_ip": None,
                "src_port": 0,
                "dst_port": 0,
                "ttl": 0,
                "tcp_flags": "",
            }

            if IP not in pkt:
                return base

            ip_layer = pkt[IP]
            base["src_ip"] = ip_layer.src
            base["dst_ip"] = ip_layer.dst
            base["ttl"] = ip_layer.ttl

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                base["protocol"] = "TCP"
                base["src_port"] = tcp_layer.sport
                base["dst_port"] = tcp_layer.dport
                base["tcp_flags"] = str(tcp_layer.flags)
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                base["protocol"] = "UDP"
                base["src_port"] = udp_layer.sport
                base["dst_port"] = udp_layer.dport
            elif ICMP in pkt:
                base["protocol"] = "ICMP"

            return base

        except Exception as e:
            logger.debug(f"Failed to parse packet {idx}: {e}")
            return None

    def to_dataframe(self):
        """Convert all parsed packets to pandas DataFrame."""
        import pandas as pd
        return pd.DataFrame(list(self.iter_packets()))


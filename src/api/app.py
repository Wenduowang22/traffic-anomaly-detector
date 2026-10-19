"""
FastAPI web service interface
REST API for PCAP upload and anomaly detection.
"""
import tempfile
import os
import logging
from typing import List, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel

from ..config import LOG_FORMAT, LOG_DATE_FORMAT, DEFAULT_CONTAMINATION
from ..traffic_parser import TrafficParser
from ..feature_extractor import FeatureExtractor
from ..detector import AnomalyDetector

logger = logging.getLogger("tad.api")
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=logging.INFO)

app = FastAPI(
    title="Traffic Anomaly Detector API",
    description="Unsupervised network traffic anomaly detection service",
    version="1.0.0",
)


class AnomalyResult(BaseModel):
    flow_key: str
    packet_count: int
    total_bytes: int
    anomaly_score: float


class DetectionResponse(BaseModel):
    code: int
    message: str
    total_packets: int
    total_flows: int
    anomaly_count: int
    anomaly_ratio: float
    top_anomalies: List[Dict[str, Any]]


@app.get("/api/health", summary="Service health check")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/api/detect", response_model=DetectionResponse, summary="Upload PCAP for anomaly detection")
async def detect_traffic(
    file: UploadFile = File(...),
    contamination: float = DEFAULT_CONTAMINATION,
    top_n: int = 20,
):
    if not file.filename or not file.filename.endswith((".pcap", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap / .cap files are supported")

    tmp_path = None
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Parse and analyze
        parser = TrafficParser(tmp_path).load()
        packet_df = parser.to_dataframe()
        flow_df = FeatureExtractor.build_flows(packet_df)

        if flow_df.empty:
            raise HTTPException(status_code=422, detail="No valid network flows found in file")

        X = FeatureExtractor.get_feature_matrix(flow_df)
        detector = AnomalyDetector(contamination=contamination)
        detector.fit_predict(X)
        anomalies = detector.rank_anomalies(flow_df)

        top = anomalies.head(top_n).to_dict(orient="records")

        return DetectionResponse(
            code=200,
            message="Detection completed",
            total_packets=len(packet_df),
            total_flows=len(flow_df),
            anomaly_count=len(anomalies),
            anomaly_ratio=round(len(anomalies) / len(flow_df), 4),
            top_anomalies=top,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Detection error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


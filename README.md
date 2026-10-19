# Traffic Anomaly Detector

Lightweight unsupervised network traffic anomaly detection toolkit.
Based on Isolation Forest algorithm, requires no labeled training data.
Supports both CLI batch analysis and FastAPI web service, deployable via Docker.

## ✨ Features
- 📡 **Stream PCAP parsing** – memory efficient, handles large capture files
- 🧮 **Flow-level feature engineering** – 5-tuple aggregation, 15+ statistical features
- 🔍 **Unsupervised detection** – Isolation Forest, no labels required
- 💻 **CLI tool** – batch analysis with structured report output
- 🌐 **REST API** – FastAPI interface with OpenAPI documentation
- 🐳 **Docker ready** – multi-stage build, one command deployment

## 🛠️ Tech Stack
| Category | Technology |
|----------|------------|
| Language | Python 3.10+ |
| Traffic parsing | Scapy |
| ML | Scikit-learn (Isolation Forest) |
| Web | FastAPI + Uvicorn |
| Data | Pandas, NumPy |
| Container | Docker |

## 🚀 Quick Start

### Option 1: CLI
```bash
# Install
pip install .

# Run analysis
tad --pcap data/sample.pcap --top 10


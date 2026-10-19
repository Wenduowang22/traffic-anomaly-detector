"""Global configuration constants"""
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# Detection defaults
DEFAULT_CONTAMINATION = 0.05
DEFAULT_N_ESTIMATORS = 120
RANDOM_SEED = 42

# Feature engineering
FLOW_TIMEOUT_SEC = 30.0

# Logging
LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


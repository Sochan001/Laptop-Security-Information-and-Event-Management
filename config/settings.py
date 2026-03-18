from pathlib import Path

# Base directory (root of my project)
BASE_DIR = Path(__file__).resolve().parent.parent

# Log directories
LOG_DIR = BASE_DIR / "logs"
RAW_LOG_DIR = LOG_DIR / "raw_logs"
PROCESSED_DIR = LOG_DIR / "processed"
AUTH_LOG = RAW_LOG_DIR / "auth_events.jsonl"

import sys
import json
import os
import threading
import tkinter as tk
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import AUTH_LOG, APP_LOG, PHOTOS_DIR
from analysis.suspicious_detector import (
    detect_failed_logins,
    detect_unusual_login_times,
    detect_brute_force,
)

#=========== Colours ================================================================
BG_DARK      = "#0d1117"
BG_SIDEBAR   = "#161b22"
BG_CARD      = "#1c2128"
BG_ALERT     = "#161b22"
ACCENT_BLUE  = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED   = "#f85149"
ACCENT_AMBER = "#d29922"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"

#==============Fonts ================================================================
FONT_TITLE   = ("Consolas", 18, "bold")
FONT_NAV     = ("Consolas", 11)
FONT_STAT_LG = ("Consolas", 28, "bold")
FONT_STAT_SM = ("Consolas", 10)
FONT_MONO    = ("Consolas", 9)
FONT_ALERT   = ("Consolas", 10)


#==============Data helpers =========================================================
def load_auth_counts():
    counts = {
        "LOGIN_SUCCESS": 0,
        "LOGIN_FAILED": 0,
        "WORKSTATION_LOCKED": 0,
        "WORKSTATION_UNLOCKED": 0,
    }
    one_week_ago = datetime.now() - timedelta(days=7)

    if not AUTH_LOG.exists():
        return counts

    with open(AUTH_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                ts = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
                if ts >= one_week_ago and record["event_type"] in counts:
                    counts[record["event_type"]] += 1
            except Exception:
                pass
    return counts


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


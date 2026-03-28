from analysis.suspicious_detector import (
    detect_failed_logins,
    detect_unusual_login_times,
    detect_brute_force,
)
from config.settings import AUTH_LOG, APP_LOG, PHOTOS_DIR
import sys
import json
import os
import threading
import tkinter as tk
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# =========== Colours ================================================================
BG_DARK = "#0d1117"
BG_SIDEBAR = "#161b22"
BG_CARD = "#1c2128"
BG_ALERT = "#161b22"
ACCENT_BLUE = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED = "#f85149"
ACCENT_AMBER = "#d29922"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED = "#8b949e"
BORDER = "#30363d"

# ==============Fonts ================================================================
FONT_TITLE = ("Consolas", 18, "bold")
FONT_NAV = ("Consolas", 11)
FONT_STAT_LG = ("Consolas", 28, "bold")
FONT_STAT_SM = ("Consolas", 10)
FONT_MONO = ("Consolas", 9)
FONT_ALERT = ("Consolas", 10)


# ==============Data helpers =========================================================
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
                ts = datetime.strptime(
                    record["timestamp"], "%Y-%m-%d %H:%M:%S")
                if ts >= one_week_ago and record["event_type"] in counts:
                    counts[record["event_type"]] += 1
            except Exception:
                pass
    return counts


def load_alerts():
    alerts = []
    failed = detect_failed_logins()
    if failed:
        alerts.append(f"⚠  {len(failed)} failed login attempt(s) detected")
    if len(failed) >= 3:
        alerts.append("🔴  ALERT: More than 3 failed logins — possible attack")
    if detect_brute_force():
        alerts.append("🔴  ALERT: Brute force pattern detected")
    if detect_unusual_login_times():
        alerts.append("🟡  Unusual login time detected (00:00–05:00)")
    if not alerts:
        alerts.append("✅  No suspicious activity detected")
    return alerts


# ==============Pie chart drawn on Canvas =========================================================

def draw_pie(canvas, counts):
    canvas.delete("all")

    total = sum(counts.values())
    if total == 0:
        canvas.create_text(105, 100, text="No data",
                           fill=TEXT_MUTED, font=FONT_ALERT)
        return

    colours = [ACCENT_GREEN, ACCENT_RED, ACCENT_AMBER, ACCENT_BLUE]
    labels = ["Success", "Failed", "Locked", "Unlocked"]
    values = [
        counts["LOGIN_SUCCESS"],
        counts["LOGIN_FAILED"],
        counts["WORKSTATION_LOCKED"],
        counts["WORKSTATION_UNLOCKED"],
    ]

    cx, cy, r = 105, 90, 75
    start = 0.0

    for i, val in enumerate(values):
        if val == 0:
            continue
        extent = (val / total) * 360
        canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=start, extent=extent,
            fill=colours[i], outline=BG_DARK, width=2,
        )
        start += extent

    # Legend
    for i, (label, colour) in enumerate(zip(labels, colours)):
        y = 180 + i * 20
        canvas.create_rectangle(10, y, 22, y + 12,
                                fill=colour, outline="")
        canvas.create_text(
            28, y + 6, anchor="w",
            text=f"{label}: {values[i]}",
            fill=TEXT_MUTED, font=FONT_MONO,
        )


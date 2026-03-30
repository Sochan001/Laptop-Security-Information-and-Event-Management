import sys
import json
import os
import threading
import tkinter as tk
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.suspicious_detector import (
    detect_failed_logins,
    detect_unusual_login_times,
    detect_brute_force,
)
from config.settings import AUTH_LOG, APP_LOG, PHOTOS_DIR

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

# ==============Dashboard class =========================================================

class SIEMDashboard:

    def __init__(self, root):
        self.root = root
        self.root.title("Personal SIEM")
        self.root.geometry("1000x640")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)

        self._monitor_running = False
        self._monitor_thread = None

        self._build_ui()
        self.refresh_data()

    # ==============Build UI =========================================================

    def _build_ui(self):
        # Title bar
        title_bar = tk.Frame(self.root, bg=BG_DARK, pady=12)
        title_bar.pack(fill="x", padx=20)

        tk.Label(
            title_bar, text="🛡  Personal SIEM",
            bg=BG_DARK, fg=ACCENT_BLUE, font=FONT_TITLE,
        ).pack(side="left")

        self.last_scan_label = tk.Label(
            title_bar, text="Last scan: —",
            bg=BG_DARK, fg=TEXT_MUTED, font=FONT_MONO,
        )
        self.last_scan_label.pack(side="right", padx=10)

        # Divider
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        # Body: resizable sidebar + main content
        body = tk.PanedWindow(
            self.root, orient="horizontal",
            sashwidth=4, bg=BORDER, sashrelief="flat",
        )
        body.pack(fill="both", expand=True)

        sidebar = tk.Frame(body, bg=BG_SIDEBAR, width=160)
        body.add(sidebar, minsize=120)
        self._build_sidebar(sidebar)

        main = tk.Frame(body, bg=BG_DARK)
        body.add(main, minsize=500)
        self._build_main(main)

        # Alert bar at bottom
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")
        alert_bar = tk.Frame(self.root, bg=BG_ALERT, pady=8)
        alert_bar.pack(fill="x")

        tk.Label(
            alert_bar, text="ALERTS",
            bg=BG_ALERT, fg=ACCENT_AMBER,
            font=("Consolas", 9, "bold"), padx=12,
        ).pack(anchor="w")

        self.alert_text = tk.Label(
            alert_bar, text="Loading…",
            bg=BG_ALERT, fg=TEXT_PRIMARY,
            font=FONT_ALERT, justify="left",
            padx=12, wraplength=900,
        )
        self.alert_text.pack(anchor="w")

    def _build_sidebar(self, parent):
        tk.Label(
            parent, text="NAVIGATE",
            bg=BG_SIDEBAR, fg=TEXT_MUTED,
            font=("Consolas", 8, "bold"), pady=16,
        ).pack(fill="x", padx=12)

        nav_items = [
            ("📊  Dashboard", self.show_dashboard),
            ("📄  Reports",   self.show_report),
            ("📷  Photos",    self.open_photos),
            ("📋  Running Apps", self.show_running_apps),
        ]

        for text, cmd in nav_items:
            btn = tk.Button(
                parent, text=text, command=cmd,
                bg=BG_SIDEBAR, fg=TEXT_PRIMARY,
                font=FONT_NAV, anchor="w",
                relief="flat", cursor="hand2",
                activebackground=BG_CARD,
                activeforeground=ACCENT_BLUE,
                padx=12, pady=8, bd=0,
            )
            btn.pack(fill="x", pady=1)

        # Push scan button to bottom
        tk.Frame(parent, bg=BG_SIDEBAR).pack(fill="both", expand=True)

        self.scan_btn = tk.Button(
            parent, text="▶  Start Monitor",
            command=self.toggle_monitor,
            bg=ACCENT_GREEN, fg="#0d1117",
            font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2",
            pady=10, bd=0,
        )
        self.scan_btn.pack(fill="x", padx=12, pady=12)

    def _build_main(self, parent):
        top_row = tk.Frame(parent, bg=BG_DARK)
        top_row.pack(fill="both", expand=True, padx=16, pady=16)

        # Stat cards on the left
        stats_frame = tk.Frame(top_row, bg=BG_DARK)
        stats_frame.pack(side="left", fill="both", expand=True)

        self.stat_vars = {}
        stat_defs = [
            ("LOGIN_SUCCESS",        "Successful Logins",    ACCENT_GREEN),
            ("LOGIN_FAILED",         "Failed Logins",        ACCENT_RED),
            ("WORKSTATION_LOCKED",   "Workstation Locked",   ACCENT_AMBER),
            ("WORKSTATION_UNLOCKED", "Workstation Unlocked", ACCENT_BLUE),
        ]

        for key, label, colour in stat_defs:
            card = tk.Frame(stats_frame, bg=BG_CARD,
                            pady=10, padx=16)
            card.pack(fill="x", pady=4)

            var = tk.StringVar(value="—")
            self.stat_vars[key] = var

            tk.Label(
                card, textvariable=var,
                bg=BG_CARD, fg=colour, font=FONT_STAT_LG,
            ).pack(side="left")

            tk.Label(
                card, text=label,
                bg=BG_CARD, fg=TEXT_MUTED, font=FONT_STAT_SM,
                padx=12,
            ).pack(side="left", anchor="s", pady=6)

        # Pie chart on the right
        chart_frame = tk.Frame(top_row, bg=BG_CARD, width=220)
        chart_frame.pack(side="right", fill="y", padx=(16, 0))

        tk.Label(
            chart_frame, text="Event Breakdown",
            bg=BG_CARD, fg=TEXT_MUTED,
            font=("Consolas", 9, "bold"), pady=8,
        ).pack()

        self.pie_canvas = tk.Canvas(
            chart_frame, width=210, height=270,
            bg=BG_CARD, highlightthickness=0,
        )
        self.pie_canvas.pack(padx=5, pady=5)

        # Refresh button
        tk.Button(
            parent, text="↻  Refresh",
            command=self.refresh_data,
            bg=BG_CARD, fg=ACCENT_BLUE,
            font=("Consolas", 9), relief="flat",
            cursor="hand2", pady=4,
        ).pack(anchor="e", padx=16, pady=(0, 12))

    # ==============Actions =========================================================

    def refresh_data(self):
        counts = load_auth_counts()
        for key, var in self.stat_vars.items():
            var.set(str(counts[key]))
        draw_pie(self.pie_canvas, counts)
        alerts = load_alerts()
        self.alert_text.config(text="\n".join(alerts))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_label.config(text=f"Last scan: {now}")

    def show_dashboard(self):
        self.refresh_data()

    def show_report(self):
        import io
        from contextlib import redirect_stdout
        from reports.report_generator import generate_report

        popup = tk.Toplevel(self.root)
        popup.title("Weekly Report")
        popup.geometry("600x400")
        popup.configure(bg=BG_DARK)

        text = tk.Text(
            popup, bg=BG_CARD, fg=TEXT_PRIMARY,
            font=FONT_MONO, padx=12, pady=12, relief="flat",
        )
        text.pack(fill="both", expand=True, padx=12, pady=12)

        buf = io.StringIO()
        with redirect_stdout(buf):
            generate_report()

        text.insert("1.0", buf.getvalue())
        text.config(state="disabled")

    def open_photos(self):
        if PHOTOS_DIR.exists():
            os.startfile(str(PHOTOS_DIR))
        else:
            tk.messagebox.showinfo("Photos", "No photos folder found yet.")
    
    def show_running_apps(self):
        from collector.app_collector import get_running_apps

        popup = tk.Toplevel(self.root)
        popup.title("Running Applications")
        popup.geometry("400x300")
        popup.configure(bg=BG_DARK)

        text = tk.Text(
            popup, bg=BG_CARD, fg=TEXT_PRIMARY,
            font=FONT_MONO, padx=12, pady=12, relief="flat",
        )
        text.pack(fill="both", expand=True, padx=12, pady=12)

        apps = get_running_apps()
        if apps:
            text.insert("1.0", "\n".join(apps))
        else:
            text.insert("1.0", "No running applications detected.")
        text.config(state="disabled")

    def toggle_monitor(self):
        if self._monitor_running:
            self._monitor_running = False
            self.scan_btn.config(text="▶  Start Monitor", bg=ACCENT_GREEN)
        else:
            self._monitor_running = True
            self.scan_btn.config(text="⏹  Stop Monitor", bg=ACCENT_RED)
            self._monitor_thread = threading.Thread(
                target=self._run_monitor_loop, daemon=True,
            )
            self._monitor_thread.start()

    def _run_monitor_loop(self):
        import win32event
        import win32evtlog
        from collector.auth_collector import read_auth_events, save_events, check_and_capture
    
        event_handle = win32event.CreateEvent(None, 0, 0, None)
        log_handle = win32evtlog.OpenEventLog(None, "Security")
        win32evtlog.NotifyChangeEventLog(log_handle, event_handle)
        processed = set()
    
        while self._monitor_running:
            win32event.WaitForSingleObject(event_handle, 1000)
            if not self._monitor_running:
                break
            records = read_auth_events()
            save_events(records)
            for record in records:
                if record["timestamp"] not in processed:
                    processed.add(record["timestamp"])
                    check_and_capture(record)
            self.root.after(0, self.refresh_data)
    
        win32evtlog.CloseEventLog(log_handle)


# ==============Entry point =========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = SIEMDashboard(root)
    root.mainloop()


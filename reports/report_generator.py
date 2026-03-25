from pathlib import Path
from datetime import datetime, timedelta
import sys
import json
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analysis.suspicious_detector import detect_failed_logins, detect_unusual_login_times, detect_brute_force
from config.settings import AUTH_LOG
from config.settings import APP_LOG
def generate_report():
    one_week_ago = datetime.now() - timedelta(days=7)
    with open(AUTH_LOG, "r") as f:
        auth_events = []
        for line in f:
            record = json.loads(line)
            event_time = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
            if event_time >= one_week_ago:
                auth_events.append(record)
        s, fa, w, u = 0, 0, 0, 0
        for record in auth_events:
            if record["event_type"] == "LOGIN_SUCCESS":
                s += 1
            elif record["event_type"] == "LOGIN_FAILED":
                fa += 1
            elif record["event_type"] == "WORKSTATION_LOCKED":
                w += 1
            elif record["event_type"] == "WORKSTATION_UNLOCKED":
                u += 1
        print(f""" 
            ======================================
                    PERSONAL SIEM WEEKLY REPORT
            ======================================
            ||        LOGIN_SUCCESS:        {s}        ||
            ||        LOGIN_FAILED:         {fa}          ||
            ||        WORKSTATION_LOCKED:   {w}         ||
            ||        WORKSTATION_UNLOCKED: {u}         ||
            ===========================================""")
        failed= detect_failed_logins()
        unusual = detect_unusual_login_times()
        brute_force = detect_brute_force()
        print (f"""
               ======================================
                    SUSPICIOUS ACTIVITY
            ======================================
            || Failed Login Attempts: {len(failed) if failed else 0} ||
            || Unusual Login Times: {"Yes" if unusual else "No"}  ||
            || Brute Force Attack: {"Yes" if brute_force else "No"}  ||
            ======================================
        """)
        if failed and len(failed) >=3:
            print("\n⚠  ALERT: SUSPICIOUS!!! More than 3 failed login attempts detected!")
        if unusual:
            print("\n⚠  ALERT: SUSPICIOUS!!! Unusual login times detected!")
        if brute_force:
            print("\n⚠  ALERT: SUSPICIOUS!!! Potential brute force attack detected!")

generate_report()
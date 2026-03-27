import sys
import json
import win32evtlog
import time
import win32event
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from collector.app_collector import get_running_apps
from config.settings import APP_LOG
from config.settings import AUTH_LOG
from datetime import datetime, timedelta
from collector.camera_collector import capture_photo
# Events which are important
EVENT_MAP = {
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILED",
    4800: "WORKSTATION_LOCKED",
    4801: "WORKSTATION_UNLOCKED",
}


def read_auth_events():
    server = None
    log_type = "Security"

    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print("Reading auth events...\n")
    c = 0
    records = []

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            event_id = event.EventID & 0xFFFF
            if event_id in EVENT_MAP:
                record = {
                    "timestamp":  str(event.TimeGenerated),
                    "event_type": EVENT_MAP[event_id],
                    "event_id":   event_id,
                    "user": event.StringInserts[5] if event.StringInserts and len(event.StringInserts) > 5 else "Unknown"
                }
                records.append(record)
                c += 1
    win32evtlog.CloseEventLog(hand)
    return records


def save_events(records):
    with open(AUTH_LOG, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    print(f"Saved {len(records)} events to {AUTH_LOG}")


def summary(records):
    print(f"\nSummary:")
    s, fa, w, u = 0, 0, 0, 0
    for record in records:
        if record["event_type"] == "LOGIN_SUCCESS":
            s += 1
        elif record["event_type"] == "LOGIN_FAILED":
            fa += 1
        elif record["event_type"] == "WORKSTATION_LOCKED":
            w += 1
        elif record["event_type"] == "WORKSTATION_UNLOCKED":
            u += 1
    print(f"LOGIN_SUCCESS: {s}")
    print(f"LOGIN_FAILED: {fa}")
    print(f"WORKSTATION_LOCKED: {w}")
    print(f"WORKSTATION_UNLOCKED: {u}")
    if fa >= 3:
        print("\nALERT: SUSPICIOUS!!! More than 3 failed login attempts detected!")


def check_and_capture(records):
    for record in records:
        print(
            f"{record['timestamp']}  |  {record['event_type']} | {record['user']}")
        event_time = datetime.strptime(
            record["timestamp"], "%Y-%m-%d %H:%M:%S")
        if record["event_id"] == 4801 and datetime.now() - event_time < timedelta(minutes=2):
            apps = get_running_apps()
            with open(APP_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(
                    {"timestamp": record["timestamp"], "trigger": "UNLOCK", "apps": list(apps)}) + "\n")
            capture_photo("Suspicious_UNLOCKED")
        if record["event_id"] == 4625 and datetime.now() - event_time < timedelta(minutes=2):
            apps = get_running_apps()
            with open(APP_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(
                    {"timestamp": record["timestamp"], "trigger": "LOGIN_FAILED", "apps": list(apps)}) + "\n")
            capture_photo("Suspicious_LOGIN_FAILED")


def run_monitor():
    try:
        while True:
            records = read_auth_events()
            save_events(records)
            check_and_capture(records)
            summary(records)
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        print("\nStopping auth monitor...")


def watch_events():
    event_handle = win32event.CreateEvent(None, 0, 0, None)
    log_handle = win32evtlog.OpenEventLog(None, "Security")
    win32evtlog.NotifyChangeEventLog(log_handle, event_handle)
    while True:
        try: 
            win32event.WaitForSingleObject(event_handle, win32event.INFINITE)
            records = read_auth_events()
            save_events(records)
            check_and_capture(records)
        except KeyboardInterrupt:
            print("\nStopping auth monitor...")
            break

watch_events()
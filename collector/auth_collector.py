from collector.camera_collector import capture_photo
from datetime import datetime, timedelta
from config.settings import AUTH_LOG
import json
import win32evtlog
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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
    c=0
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
                c+=1
    win32evtlog.CloseEventLog(hand)
    return records

def save_events(records):
    with open(AUTH_LOG, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    print(f"Saved {len(records)} events to {AUTH_LOG}")
records = read_auth_events()
save_events(records)

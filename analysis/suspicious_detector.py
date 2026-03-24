from datetime import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from config.settings import AUTH_LOG
def detect_failed_logins():
    print("Analysing auth events...\n")

    failed = []
    with open(AUTH_LOG, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["event_type"] == "LOGIN_FAILED":
                failed.append(record)

    if failed:
        print(f"⚠  Found {len(failed)} failed login attempts:\n")
        for event in failed:
            print(f"  {event['timestamp']}  |  EventID: {event['event_id']} | User: {event['user']}")
    else:
        print("✓  No failed login attempts found.")
    if len(failed) >=3:
            print("\nALERT: SUSPICIOUS!!! More than 3 failed login attempts detected!")

def detect_unusual_login_times():
    with open(AUTH_LOG, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            event_time = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
            if record["event_type"] == "LOGIN_SUCCESS" and event_time.hour <= 5:
                print(f"⚠  Unusual login time detected: {record['timestamp']} for user {record['user']}")
detect_failed_logins()
detect_unusual_login_times()
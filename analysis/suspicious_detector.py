import json
from pathlib import Path

INPUT_FILE = Path(__file__).resolve().parent.parent / "logs" / "raw_logs" / "auth_events.jsonl"

def detect_failed_logins():
    print("Analysing auth events...\n")

    failed = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["event_type"] == "LOGIN_FAILED":
                failed.append(record)

    if failed:
        print(f"⚠  Found {len(failed)} failed login attempts:\n")
        for event in failed:
            print(f"  {event['timestamp']}  |  EventID: {event['event_id']}")
    else:
        print("✓  No failed login attempts found.")
    if len(failed) >=3:
            print("\nALERT: SUSPICIOUS!!! More than 3 failed login attempts detected!")


detect_failed_logins()
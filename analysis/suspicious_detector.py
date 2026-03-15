import json
from pathlib import Path

INPUT_FILE = Path(__file__).resolve().parent.parent / "logs" / "raw_logs" / "auth_events.jsonl"

def detect_failed_logins():
    print("Analysing auth events...\n")

    failed = []
    #Temporary test records
    test_records = [
        {"timestamp": "2026-03-14 02:13:00", "event_type": "FAILED", "event_id": 4625},
        {"timestamp": "2026-03-14 02:13:05", "event_type": "FAILED", "event_id": 4625},
        {"timestamp": "2026-03-14 02:13:10", "event_type": "FAILED", "event_id": 4625},
    ]

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["event_type"] == "FAILED":
                failed.append(record)
    failed.extend(test_records)  # Adding test records to the list

    if failed:
        print(f"⚠  Found {len(failed)} failed login attempts:\n")
        for event in failed:
            print(f"  {event['timestamp']}  |  EventID: {event['event_id']}")
    else:
        print("✓  No failed login attempts found.")

detect_failed_logins()
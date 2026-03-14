import win32evtlog
import json
from datetime import datetime
from pathlib import Path

# Path to save events
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "logs" / "raw_logs" / "auth_events.jsonl"

def read_login_events():
    server = None
    log_type = "Security"

    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print("Reading login events...\n")

    count = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                event_id = event.EventID & 0xFFFF
                if event_id in (4624, 4625):
                    label = "SUCCESS" if event_id == 4624 else "FAILED"

                    record = {
                        "timestamp": str(event.TimeGenerated),
                        "event_type": label,
                        "event_id": event_id,
                    }

                    f.write(json.dumps(record) + "\n")
                    print(f"{record['timestamp']}  |  {record['event_type']}")

                    count += 1
                    if count >= 20:
                        break
            if count >= 20:
                break

    win32evtlog.CloseEventLog(hand)
    print(f"\nSaved {count} events to {OUTPUT_FILE}")

read_login_events()
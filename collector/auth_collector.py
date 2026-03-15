import win32evtlog
import json
from pathlib import Path

OUTPUT_FILE = Path(__file__).resolve().parent.parent / \
    "logs" / "raw_logs" / "auth_events.jsonl"

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

    count = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
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
                    }
                    f.write(json.dumps(record) + "\n")
                    print(f"{record['timestamp']}  |  {record['event_type']}")
                    count += 1
                    if count >= 100:
                        break
            if count >= 100:
                break

    win32evtlog.CloseEventLog(hand)

    print(f"\nSaved {count} events to {OUTPUT_FILE}")
    print(f"\nSummary:")
    print(
        f"  LOGIN_SUCCESS:        {sum(1 for e in open(OUTPUT_FILE) if 'LOGIN_SUCCESS' in e)}")
    print(
        f"  LOGIN_FAILED:         {sum(1 for e in open(OUTPUT_FILE) if 'LOGIN_FAILED' in e)}")
    print(
        f"  WORKSTATION_LOCKED:   {sum(1 for e in open(OUTPUT_FILE) if 'WORKSTATION_LOCKED' in e)}")
    print(
        f"  WORKSTATION_UNLOCKED: {sum(1 for e in open(OUTPUT_FILE) if 'WORKSTATION_UNLOCKED' in e)}")


read_auth_events()

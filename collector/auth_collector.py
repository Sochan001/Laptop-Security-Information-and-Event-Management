import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import win32evtlog
import json
from config.settings import AUTH_LOG
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

    with open(AUTH_LOG, "w", encoding="utf-8") as f:
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
                    f.write(json.dumps(record) + "\n")
                    print(f"{record['timestamp']}  |  {record['event_type']} | {record['user']}")
                    count += 1
                    if count >= 100:
                        break
            if count >= 100:
                break

    win32evtlog.CloseEventLog(hand)

    print(f"\nSaved {count} events to {AUTH_LOG}")
    print(f"\nSummary:")
    s,fa,w,u=0,0,0,0
    for e in open(AUTH_LOG):
        if 'LOGIN_SUCCESS' in e:
            s= s+1
    print(f"LOGIN_SUCCESS: {s}")
    for e in open(AUTH_LOG):
        if 'LOGIN_FAILED' in e:
            fa= fa+1
    print(f"LOGIN_FAILED: {fa}")
    for e in open(AUTH_LOG):        
        if 'WORKSTATION_LOCKED' in e:
            w= w+1
    print(f"WORKSTATION_LOCKED: {w}")
    for e in open(AUTH_LOG):        
        if 'WORKSTATION_UNLOCKED' in e:
            u= u+1
    print(f"WORKSTATION_UNLOCKED: {u}")
    if fa >= 3:
        print("\nALERT: SUSPICIOUS!!! More than 3 failed login attempts detected!")

read_auth_events()

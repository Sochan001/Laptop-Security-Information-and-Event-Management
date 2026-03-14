import win32evtlog

def read_login_events():
    server = None  # local machine
    log_type = "Security"

    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_S_READ

    print("Reading login events...\n")

    count = 0

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            event_id = event.EventID & 0xFFFF
            if event_id in (4624, 4625):
                label = "SUCCESS" if event_id == 4624 else "FAILED"
                print(f"{event.TimeGenerated}  |  {label}  |  EventID: {event_id}")
                count += 1
                if count >= 20:
                    break
        if count >= 20:
            break

    win32evtlog.CloseEventLog(hand)
    print("\nDone.")

read_login_events()
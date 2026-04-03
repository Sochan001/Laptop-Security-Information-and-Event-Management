# Laptop Security Information and Event Management
This tool acts as a constantly monitoring application that will monitor and track every login whether it fails or gets successful. Whenever any user types the wrong password/ login fails, the tool will capture the photo of the user and saves it in:
```
logs\Photos
```
and whenever the authorized user logins and checks the file, they can know the details of the unauthorized user and can also know what apps they were using when they logged in.

---

## Features

- **Real-time authentication monitoring** — detects login success, login failures, workstation lock and unlock events via Windows Security Event Log
- **Instant photo capture** — takes a photo using your webcam the moment a workstation unlock or failed login is detected
- **Application tracking** — records which applications were running at the time of each security event
- **Suspicious activity detection** — detects brute force patterns, unusual hour logins, and multiple failed login attempts
- **Weekly security report** — summarises all events from the last 7 days
- **Live dashboard** — Tkinter GUI with real-time stats, pie chart, alerts, and navigation

---

## Project Structure

```
personal-siem/
│
├── config/
│   └── settings.py              # Centralised paths and configuration
│
├── collector/
│   ├── auth_collector.py        # Reads Windows Security Event Log
│   ├── camera_collector.py      # Captures photos via webcam
│   └── app_collector.py         # Gets list of running processes
│
├── analysis/
│   └── suspicious_detector.py   # Detection rules and alert logic
│
├── reports/
│   └── report_generator.py      # Weekly HTML/text report
│
├── dashboard/
│   └── viewer.py                # Tkinter GUI dashboard
│
├── logs/
│   ├── raw_logs/
│   │   ├── auth_events.jsonl    # All auth events
│   │   └── app_events.jsonl     # App snapshots at security events
│   ├── processed/
│   └── Photos/                  # Captured photos
│
├── requirements.txt
└── README.md
```


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
---

## Windows Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 4624 | Successful login |
| 4625 | Failed login |
| 4800 | Workstation locked |
| 4801 | Workstation unlocked |

---

## Prerequisites

- Windows 10 or 11
- Python 3.10 or higher
- Administrator privileges (required to read Windows Security Event Log)

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/Sochan001/Laptop-Security-Information-and-Event-Management.git
cd Laptop-Security-Information-and-Event-Management
```

**2. Create and activate a virtual environment**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Enable lock/unlock event logging (run once as Administrator)**
```powershell
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
```

---

## Usage

**Run the dashboard**
```bash
python dashboard/viewer.py
```

**Run the collector directly (terminal mode)**
```bash
python collector/auth_collector.py
```

**Generate a report manually**
```bash
python reports/report_generator.py
```

---

## Dashboard Guide

| Button | Action |
|--------|--------|
| 📊 Dashboard | View live stats and pie chart |
| 📄 Reports | View weekly security report |
| 📷 Photos | Open captured photos folder |
| 📋 Running Apps | View currently running applications |
| ▶ Start Monitor | Begin real-time event monitoring |
| ⏹ Stop Monitor | Stop monitoring |
| ↻ Refresh | Reload data from logs |

---

## Detection Rules

| Rule | Trigger |
|------|---------|
| Multiple failed logins | 3 or more failed attempts |
| Brute force pattern | 3+ failures within 5 minutes |
| Unusual hour login | Successful login between 00:00 and 05:00 |
| Photo on unlock | Webcam capture on workstation unlock |
| Photo on failed login | Webcam capture on failed login attempt |

---

## Future Work & Recommendations

- **System clock tampering detection** — Event ID 4616 flags when someone changes the system clock to avoid detection
- **Email alerts** — Send an email notification when suspicious activity is detected
- **Web dashboard** — Replace Tkinter with a Flask web interface accessible from any device on the network
- **File integrity monitoring** — Detect changes to sensitive folders like Documents and Desktop
- **Network connection monitoring** — Alert on unknown Wi-Fi networks or VPN changes
- **Fingerprint vs password distinction** — Differentiate between biometric and password authentication in event logs
- **Log rotation** — Automatically archive old logs to prevent the log file growing too large
- **Installer / startup script** — Auto-start the monitor when Windows boots using Task Scheduler

---

## Built With

- [pywin32](https://pypi.org/project/pywin32/) — Windows Event Log access
- [opencv-python](https://pypi.org/project/opencv-python/) — Webcam photo capture
- [psutil](https://pypi.org/project/psutil/) — Running process monitoring
- [tkinter](https://docs.python.org/3/library/tkinter.html) — GUI dashboard (built into Python)

---

## Author

Sochan Dangol — built as a hands-on Python learning project

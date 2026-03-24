from pathlib import Path
import sys
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import AUTH_LOG
from config.settings import APP_LOG
def generate_report():
    with open(AUTH_LOG, "r") as f:
        auth_events = []    
        for line in f:
            auth_events.append(json.loads(line))
        s, fa, w, u = 0, 0, 0, 0
        for record in auth_events:
            if record["event_type"] == "LOGIN_SUCCESS":
                s += 1
            elif record["event_type"] == "LOGIN_FAILED":
                fa += 1
            elif record["event_type"] == "WORKSTATION_LOCKED":
                w += 1
            elif record["event_type"] == "WORKSTATION_UNLOCKED":
                u += 1
        print(f""" 
            ======================================
                    PERSONAL SIEM WEEKLY REPORT
            ======================================
            ||        LOGIN_SUCCESS:        {s}        ||
            ||        LOGIN_FAILED:         {fa}          ||
            ||        WORKSTATION_LOCKED:   {w}         ||
            ||        WORKSTATION_UNLOCKED: {u}         ||
            ===========================================""")
        
generate_report()
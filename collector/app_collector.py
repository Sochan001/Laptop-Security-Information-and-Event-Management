import psutil

def get_running_apps():
    SYSTEM_PROCESSES = {
        "svchost.exe", "conhost.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "smss.exe", "fontdrvhost.exe",
        "dwm.exe", "winlogon.exe", "Registry", "System", "MemCompression",
        "System Idle Process", "WUDFHost.exe", "WmiPrvSE.exe", "pwsh.exe",
        "RuntimeBroker.exe", "taskhostw.exe", "sihost.exe", "explorer.exe",
        "msedgewebview2.exe","CefSharp.BrowserSubprocess.exe","audiodg.exe", 
        "SearchIndexer.exe", "SearchFilterHost.exe", "SearchProtocolHost.exe", 
        "OneDrive.exe", "OneDriveSetup.exe", "OneDriveStandaloneUpdater.exe", 
        "OneDriveUpdater.exe", "OneDriveTelemetry.exe", "OneDriveUpdaterService.exe"
    }
    
    apps=set()
    for process in psutil.process_iter():
        try:
            if process.name() not in SYSTEM_PROCESSES:
                apps.add(process.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return apps
apps=get_running_apps()
print("Running applications:")
for app in apps:
    print(app)
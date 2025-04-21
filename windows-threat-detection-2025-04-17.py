import win32evtlog
import pandas as pd
from collections import Counter
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import ctypes
import sys

# Suspicious Event IDs and severity levels
SUSPICIOUS_EVENT_IDS = {
    "4625": "Failed Logon",
    "4673": "Privileged Service Called",
    "4688": "Process Creation",
    "4104": "PowerShell Script Block Logging"
}

EVENT_SEVERITY = {
    "4625": "High",
    "4104": "High",
    "4673": "Medium",
    "4688": "Low"
}

LOG_TYPES = ["Security", "System"]
FAILED_LOGON_THRESHOLD = 5


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def fetch_event_logs(log_type, max_events=1000):
    events = []
    handle = win32evtlog.OpenEventLog(None, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        if not records:
            break
        for event in records:
            event_id = str(event.EventID & 0xFFFF)
            if event_id in SUSPICIOUS_EVENT_IDS:
                data = {
                    "TimeGenerated": event.TimeGenerated.Format(),
                    "EventID": event_id,
                    "EventType": SUSPICIOUS_EVENT_IDS[event_id],
                    "Severity": EVENT_SEVERITY[event_id],
                    "Source": event.SourceName,
                    "Message": event.StringInserts
                }
                events.append(data)
            if len(events) >= max_events:
                break
        if len(events) >= max_events:
            break

    return pd.DataFrame(events)


def detect_anomalies(df):
    alerts = []

    if df.empty or "EventID" not in df.columns or "Message" not in df.columns:
        alerts.append("[*] No suspicious events found or missing expected log fields.")
        return alerts

    failed_logons = [msg[-1] for msg in df[df["EventID"] == "4625"]["Message"].dropna()]
    user_fail_counts = Counter(failed_logons)

    for user, count in user_fail_counts.items():
        if count >= FAILED_LOGON_THRESHOLD:
            alerts.append(f"[!] Excessive failed logons for user '{user}': {count} times.")

    if not alerts:
        alerts.append("[*] No major anomalies detected.")
    return alerts


class LogMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Log Threat Detection")
        self.root.geometry("800x550")

        # Dropdowns
        self.log_choice = tk.StringVar(value="Security")
        self.severity_filter = tk.StringVar(value="All")
        self.type_filter = tk.StringVar(value="All")

        ttk.Label(root, text="Select Log Type:").pack(pady=5)
        self.log_menu = ttk.Combobox(root, textvariable=self.log_choice, values=LOG_TYPES)
        self.log_menu.pack()

        filter_frame = ttk.Frame(root)
        filter_frame.pack(pady=5)

        ttk.Label(filter_frame, text="Severity Filter:").grid(row=0, column=0, padx=5)
        self.severity_menu = ttk.Combobox(filter_frame, textvariable=self.severity_filter, values=["All", "High", "Medium", "Low"])
        self.severity_menu.grid(row=0, column=1, padx=5)

        ttk.Label(filter_frame, text="Event Type Filter:").grid(row=0, column=2, padx=5)
        self.type_menu = ttk.Combobox(filter_frame, textvariable=self.type_filter, values=["All"] + list(set(SUSPICIOUS_EVENT_IDS.values())))
        self.type_menu.grid(row=0, column=3, padx=5)

        self.scan_btn = ttk.Button(root, text="Run Scan", command=self.start_scan)
        self.scan_btn.pack(pady=10)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20)
        self.output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def start_scan(self):
        self.output.delete("1.0", tk.END)
        thread = threading.Thread(target=self.run_log_scan)
        thread.start()

    def run_log_scan(self):
        log_type = self.log_choice.get()
        severity_filter = self.severity_filter.get()
        type_filter = self.type_filter.get()

        self.output.insert(tk.END, f"[*] Scanning '{log_type}' log...\n")
        df = fetch_event_logs(log_type)

        if df.empty:
            self.output.insert(tk.END, "[*] No events matched in the selected log.\n")
            return

        # Apply filters
        if severity_filter != "All":
            df = df[df["Severity"] == severity_filter]
        if type_filter != "All":
            df = df[df["EventType"] == type_filter]

        for _, row in df.iterrows():
            color = self.get_color(row["Severity"])
            line = f"[{row['TimeGenerated']}] {row['Severity']} - {row['EventType']} from {row['Source']} - {row['Message']}\n"
            self.output.insert(tk.END, line)
            self.output.tag_add(row["Severity"], f"{float(self.output.index('end')) - 2}.0", "end")
            self.output.tag_config(row["Severity"], foreground=color)

        self.output.insert(tk.END, "\n[*] Detecting anomalies...\n")
        anomalies = detect_anomalies(df)
        for a in anomalies:
            self.output.insert(tk.END, f"{a}\n", "High")

    def get_color(self, severity):
        return {
            "High": "red",
            "Medium": "orange",
            "Low": "green"
        }.get(severity, "black")


def main():
    if not is_admin():
        print("❌ This script must be run as Administrator.")
        sys.exit(1)

    root = tk.Tk()
    app = LogMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

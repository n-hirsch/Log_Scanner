# Windows Log Threat Detection Tool

## 📋 Description
This is a Python-based tool designed to **ingest and analyze Windows Event Logs** from local endpoints. It uses a **Tkinter GUI** to provide a user-friendly interface for scanning event logs, detecting suspicious behavior, filtering results by severity or event type, and highlighting anomalies based on event data patterns.

The tool identifies suspicious activities like:
- Failed logon attempts
- Privileged service usage
- Process creation events
- PowerShell script execution

and color-codes them based on severity.

---

## 🚀 Features
- ✅ **Event Log Scanning** (Security and System logs)
- ✅ **Color-coded Alerts** by severity:
  - 🔴 High (e.g., failed logons, PowerShell execution)
  - 🟠 Medium (e.g., privileged service call)
  - 🟢 Low (e.g., standard process creation)
- ✅ **Filter Events** by severity or event type
- ✅ **Anomaly Detection** for excessive failed logon attempts
- ✅ **Multi-threaded GUI** using Tkinter for a responsive experience
- ✅ **Admin Privilege Check** (ensures correct access to Security logs)

---

## 🛠️ Requirements

Install the following dependencies via pip:

```bash
pip install -r requirements.txt
```

### Python Libraries:
- `pywin32`
- `pandas`
- `tkinter` (comes pre-installed with Python)

**Note:** You must run this script on **Windows** with **Administrator privileges** to access certain logs (e.g., Security log).

---

## 📂 Usage

1. **Run the script as Administrator:**

```bash
python windows-threat-detection.py
```

2. **Using the GUI:**
   - Select the log source (`Security` or `System`).
   - Apply optional filters for **Severity** or **Event Type**.
   - Click **Run Scan** to start analyzing the logs.
   - Results will appear in the scrollable output window.
   - Anomalies (like multiple failed logins) are automatically detected and highlighted.

---

## ⚙️ Event Definitions

| Event ID | Event Type                      | Severity |
|:--------:|:---------------------------------|:--------:|
| 4625     | Failed Logon                     | High     |
| 4104     | PowerShell Script Block Logging  | High     |
| 4673     | Privileged Service Called        | Medium   |
| 4688     | Process Creation                 | Low      |

---

## ⚠️ Important Notes

- Always run this script as **Administrator** to avoid permission errors when reading the `Security` log.
- Designed for use in **training environments**, **demo systems**, or **endpoint monitoring** within controlled environments.
- This script does **not** modify system logs — it only reads and analyzes.

---

## 📜 License
This project is released for educational and demonstration purposes.


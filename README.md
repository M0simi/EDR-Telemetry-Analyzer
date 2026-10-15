# EDR Telemetry Analyzer 🛡️

> Lightweight Log Analysis & Behavioral Detection Utility.
> **Author:** M0simi

## Overview
**EDR Telemetry Analyzer** is a command-line security tool designed to parse and analyze endpoint telemetry logs (JSON format) for suspicious process execution patterns, command-line anomalies, and known post-exploitation indicators.

## Features
* **Heuristic Log Scanning:** Scans telemetry records for malicious indicators (e.g., memory dumping signatures, encoded PowerShell, enumeration commands).
* **Zero Dependencies:** Built entirely with Python 3 Standard Library, making it fast and portable.
* **Clean CLI Output:** Formats alerts into a clear, readable incident table.

## Usage

Follow these simple steps to set up and run the analysis on your machine:

### 1. Prepare Your Telemetry Log File
Create a new JSON file inside the tool's directory named `sample_logs.json` (or any name you prefer), and populate it with your log records in valid `JSON` format. 

Example of `sample_logs.json`:
```json
[
  {
    "timestamp": "2026-06-15 08:30:12",
    "process_name": "cmd.exe",
    "command_line": "cmd.exe /c whoami /all"
  },
  {
    "timestamp": "2026-06-15 11:02:19",
    "process_name": "procdump64.exe",
    "command_line": "procdump64.exe -ma lsass.exe C:\\Temp\\lsass_dump.dmp"
  }
]
```

Run analysis against a sample log file:
```bash
python edr_analyzer.py -f sample_logs.json

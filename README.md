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
Run analysis against a sample log file:
```bash
python edr_analyzer.py -f sample_logs.json

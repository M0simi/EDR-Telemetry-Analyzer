#!/usr/bin/env python3
"""
Tool Name: EDR Telemetry Analyzer
Description: Log analysis utility to detect suspicious behavioral patterns & indicators in EDR telemetry.
Author: M0simi
Version: 1.0.0
License: MIT
"""

import sys
import argparse
import json
from datetime import datetime

BANNER = r"""
███████╗██████╗ ██████╗     ████████╗███████╗██╗     ███████╗███╗   ███╗███████╗████████╗
██╔════╝██╔══██╗██╔══██╗    ╚══██╔══╝██╔════╝██║     ██╔════╝████╗ ████║██╔════╝╚══██╔══╝
█████╗  ██║  ██║██████╔╝       ██║   █████╗  ██║     █████╗  ██╔████╔██║███████╗   ██║   
██╔══╝  ██║  ██║██╔══██╗       ██║   ██╔══╝  ██║     ██╔══╝  ██║╚██╔╝██║╚════██║   ██║   
███████╗██████╔╝██║  ██║       ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║███████║   ██║   
╚══════╝╚═════╝╚═╝  ╚═╝       ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚══════╝   ╚═╝   
                    [ EDR Telemetry Behavioral Analyzer ]
                          Author: M0simi // M0simi
"""

# Suspicious indicators / heuristics patterns
SUSPICIOUS_KEYWORDS = [
    "mimikatz", "procdump", "whoami", "net group", "powershell -enc", 
    "vssadmin delete shadows", "schtasks /create", "lsass.exe", 
    "cmd.exe /c", "certutil -urlcache", "regsvr32 /u /s /i"
]

def print_banner():
    print(BANNER)
    print("-" * 85)

def analyze_log_entry(entry):
    """Analyze a single log entry for IOCs or suspicious command lines"""
    findings = []
    details = json.dumps(entry).lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in details:
            findings.append(keyword)
            
    return findings

def main():
    parser = argparse.ArgumentParser(description="EDR Telemetry Analyzer: Behavioral detection utility by M0simi")
    parser.add_argument("-f", "--file", required=True, help="Path to EDR JSON log file")
    args = parser.parse_args()

    print_banner()
    print(f"[*] Loading telemetry log file: {args.file}...")
    
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            logs = json.load(f)
    except Exception as e:
        print(f"[-] Error reading log file: {e}")
        sys.exit(1)
        
    print(f"[+] Loaded {len(logs)} log records. Starting heuristic analysis...\n")
    print(f"{'TIMESTAMP':<20} | {'PROCESS':<20} | {'DETECTED ANOMALIES'}")
    print("-" * 85)
    
    detected_count = 0
    for record in logs:
        timestamp = record.get('timestamp', 'N/A')
        process = record.get('process_name', 'unknown.exe')
        anomalies = analyze_log_entry(record)
        
        if anomalies:
            detected_count += 1
            anomalies_str = ", ".join(anomalies)
            print(f"{timestamp:<20} | {process:<20} | [!] {anomalies_str}")
            
    print("-" * 85)
    print(f"[+] Analysis complete. Found {detected_count} suspicious events out of {len(logs)} total records.")
    print("[+] Developed by M0simi | Security Specialist & Defender.")

if __name__ == "__main__":
    main()

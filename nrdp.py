import os
import sys
import time
import requests
from collections import defaultdict
from scapy.all import sniff, IP, Raw
import re

THRESHOLD = 5
TIME_WINDOW = 300  # 5 minutes in seconds
NRDP_URL = " http://10.0.0.152/nrdp/"
TOKEN = "Logserver"
print(f"THRESHOLD: {THRESHOLD} attempts within {TIME_WINDOW} seconds")

SQL_INJECTION_PATTERNS = [
    r"(?:\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b).*\bFROM\b",
    r"(?:\bOR\b|\bAND\b).*=.*--",
    r"\bUNION\b.*\bSELECT\b",
    r"\bDROP\b.*\bTABLE\b",
    r"\bCREATE\b.*\bTABLE\b"
]

XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"\bon[a-z]+\s*=\s*['\"]?.*['\"]?",
    r"<.*?javascript:.*?>",
    r"<.*?\balert\b.*?>",
    r"<.*?\bconsole\.log\b.*?>"
]

def send_nrdp_notification(ip_address, alert_type, details):
    payload = {
        "token": TOKEN,
        "cmd": "submitcheck",
        "hostname": "Security Detector",
        "service": f"{alert_type}: {ip_address}",
        "state": 2,  # 2 indicates critical in Nagios
        "output": f"{alert_type} detected from IP: {ip_address}. Details: {details}"
    }
    try:
        response = requests.post(NRDP_URL, data=payload)
        if response.status_code == 200:
            print(f"Notification sent to Nagios for IP: {ip_address}")
        else:
            print(f"Failed to send notification to Nagios: {response.text}")
    except Exception as e:
        print(f"Error sending notification to Nagios: {e}")

def detect_injection(packet):
    if Raw in packet:
        payload = packet[Raw].load.decode(errors="ignore")
        src_ip = packet[IP].src

        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                print(f"SQL Injection detected from {src_ip}")
                send_nrdp_notification(src_ip, "SQL Injection", payload)
                return

        for pattern in XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                print(f"XSS Attack detected from {src_ip}")
                send_nrdp_notification(src_ip, "XSS Attack", payload)
                return

def packet_callback(packet):
    src_ip = packet[IP].src
    current_time = time.time()
    
    # Record the attempt
    failed_attempts[src_ip].append(current_time)

    # Keep only attempts within the last 5 minutes
    failed_attempts[src_ip] = [timestamp for timestamp in failed_attempts[src_ip] if current_time - timestamp <= TIME_WINDOW]

    # Check if the IP has exceeded the threshold
    if len(failed_attempts[src_ip]) > THRESHOLD and src_ip not in blocked_ips:
        print(f"Blocking IP: {src_ip} due to {len(failed_attempts[src_ip])} failed attempts")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        blocked_ips.add(src_ip)
        send_nrdp_notification(src_ip, "Failed Login", "Exceeded failed login threshold")

    # Check for SQL Injection and XSS in the payload
    detect_injection(packet)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    failed_attempts = defaultdict(list)
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)

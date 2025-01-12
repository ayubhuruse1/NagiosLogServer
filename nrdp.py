import os
import sys
import time
import requests
from collections import defaultdict
from scapy.all import sniff, IP, Raw
import re

THRESHOLD = 5
TIME_WINDOW = 300  # 5 minutes in seconds
NRDP_URL = "http://10.0.0.152/nrdp/"
TOKEN = "Logserver"
print(f"THRESHOLD: {THRESHOLD} attempts within {TIME_WINDOW} seconds")

def send_nrdp_notification(ip_address, alert_type, details):
    payload = {
        "token": TOKEN,
        "cmd": "submitcheck",
        "hostname": "Failed Login Detector",
        "service": f"{alert_type}: {ip_address}",
        "state": 1 if alert_type == "Warning" else 2,  # 1 for warning, 2 for critical
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

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        current_time = time.time()

        # Record the attempt
        failed_attempts[src_ip].append(current_time)

        # Keep only attempts within the last 5 minutes
        failed_attempts[src_ip] = [timestamp for timestamp in failed_attempts[src_ip] if current_time - timestamp <= TIME_WINDOW]

        # Check if the IP has reached the warning threshold
        if len(failed_attempts[src_ip]) == THRESHOLD and src_ip not in blocked_ips:
            print(f"Warning: {src_ip} has reached {THRESHOLD} failed login attempts")
            send_nrdp_notification(src_ip, "Warning", f"{THRESHOLD} failed login attempts within {TIME_WINDOW} seconds")

        # Check if the IP has exceeded the threshold
        if len(failed_attempts[src_ip]) > THRESHOLD and src_ip not in blocked_ips:
            print(f"Blocking IP: {src_ip} due to {len(failed_attempts[src_ip])} failed attempts")
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            blocked_ips.add(src_ip)
            send_nrdp_notification(src_ip, "Critical", f"Exceeded {THRESHOLD} failed login attempts")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    failed_attempts = defaultdict(list)
    blocked_ips = set()

    print("Monitoring failed login attempts...")
    sniff(filter="ip", prn=packet_callback)

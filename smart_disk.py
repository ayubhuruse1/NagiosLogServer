#!/usr/bin/env python3
import os
import sys
import argparse

def get_disk_usage(path):
    """Get disk usage percentage for a specified path."""
    usage = os.popen(f"df -h {path} | grep -v Filesystem | awk '{{print $5}}'").readline().strip()
    usage_percent = int(usage.replace('%', ''))
    return usage_percent

def predict_disk_fill(usage_percent, usage_delta, check_interval):
    """Predict when the disk will fill up based on current usage growth rate."""
    if usage_delta <= 0:
        return "Not growing"

    time_to_fill = ((100 - usage_percent) / usage_delta) * check_interval
    return f"{time_to_fill:.2f} hours"

def check_disk_usage(path, warning_threshold):
    """Check the disk usage and print the status based on thresholds."""
    # Get disk usage percentage
    usage_percent = get_disk_usage(path)

    # Simulate a usage delta for prediction (replace with real data if available)
    usage_delta = 0.5  # Mock growth rate in percentage per hour
    check_interval = 1  # Mock check interval in hours

    # Predict time to fill
    fill_prediction = predict_disk_fill(usage_percent, usage_delta, check_interval)

    # Determine status
    if usage_percent < warning_threshold:
        print(f"OK - {usage_percent}% of disk space used. Estimated time to full: {fill_prediction}")
        sys.exit(0)
    elif usage_percent < 95:
        print(f"WARNING - {usage_percent}% of disk space used. Estimated time to full: {fill_prediction}")
        sys.exit(1)
    else:
        print(f"CRITICAL - {usage_percent}% of disk space used. Estimated time to full: {fill_prediction}")
        sys.exit(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disk Usage Monitor")
    parser.add_argument("-p", "--path", type=str, default="/", help="Path to monitor (default: /)")
    parser.add_argument("-w", "--warning", type=int, default=85, help="Warning threshold percentage (default: 85)")

    args = parser.parse_args()
    check_disk_usage(args.path, args.warning)

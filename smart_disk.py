#!/usr/bin/env python3
import os
import sys
from datetime import timedelta

def get_disk_usage(path):
    """Get total, used, and free disk space in GB, and usage percentage."""
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {path}")

    stats = os.statvfs(path)
    total = stats.f_frsize * stats.f_blocks
    free = stats.f_frsize * stats.f_bavail
    used = total - free
    usage_percent = (used / total) * 100 if total > 0 else 0

    return {
        "total": total / (1024 ** 3),  # Convert to GB
        "used": used / (1024 ** 3),   # Convert to GB
        "free": free / (1024 ** 3),   # Convert to GB
        "percent": usage_percent
    }

def predict_disk_fill(usage_percent, usage_delta, check_interval):
    """Predict when the disk will fill up based on current usage growth rate."""
    if usage_delta <= 0:
        return "Not growing"

    hours_to_fill = ((100 - usage_percent) / usage_delta) * check_interval
    days, hours = divmod(hours_to_fill, 24)
    return f"{int(days)} days and {int(hours)} hours"

def check_disk_usage(path, warning_threshold):
    """Check the disk usage and print the status based on thresholds."""
    # Get disk usage data
    disk_data = get_disk_usage(path)
    usage_percent = disk_data["percent"]

    # Simulate a usage delta for prediction (replace with real data if available)
    usage_delta = 0.5  # Mock growth rate in percentage per hour
    check_interval = 1  # Mock check interval in hours

    # Predict time to fill
    fill_prediction = predict_disk_fill(usage_percent, usage_delta, check_interval)

    # Determine status
    if usage_percent < warning_threshold:
        status_message = f"OK - {usage_percent:.2f}% of disk space used. Total: {disk_data['total']:.2f} GB, Used: {disk_data['used']:.2f} GB, Free: {disk_data['free']:.2f} GB. Estimated time to full: {fill_prediction}"
        print(status_message)
        return 0
    elif usage_percent < 95:
        status_message = f"WARNING - {usage_percent:.2f}% of disk space used. Total: {disk_data['total']:.2f} GB, Used: {disk_data['used']:.2f} GB, Free: {disk_data['free']:.2f} GB. Estimated time to full: {fill_prediction}"
        print(status_message)
        return 1
    else:
        status_message = f"CRITICAL - {usage_percent:.2f}% of disk space used. Total: {disk_data['total']:.2f} GB, Used: {disk_data['used']:.2f} GB, Free: {disk_data['free']:.2f} GB. Estimated time to full: {fill_prediction}"
        print(status_message)
        return 2

if __name__ == "__main__":
    # Manual argument parsing to replace argparse
    path = "/"
    warning_threshold = 85

    for i in range(1, len(sys.argv)):
        if sys.argv[i] in ("-p", "--path") and i + 1 < len(sys.argv):
            path = sys.argv[i + 1]
        elif sys.argv[i] in ("-w", "--warning") and i + 1 < len(sys.argv):
            warning_threshold = int(sys.argv[i + 1])

    try:
        exit_code = check_disk_usage(path, warning_threshold)
        print(f"Exiting with code: {exit_code}")  # Log exit code
    except SystemExit as e:
        print(f"SystemExit encountered with code: {e.code}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit_code = 3  # Unknown error code
    sys.exit(exit_code)

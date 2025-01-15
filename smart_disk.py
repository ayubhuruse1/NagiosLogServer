import os
import psutil
import argparse
from datetime import datetime, timedelta

# Function to calculate disk usage
def check_disk_usage(path):
    usage = psutil.disk_usage(path)
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": usage.percent
    }

# Function to forecast when disk will fill up
def predict_disk_fill(usage_percent, usage_delta, check_interval):
    if usage_delta <= 0:
        return "Not growing"

    time_to_fill = ((100 - usage_percent) / usage_delta) * check_interval
    return str(timedelta(hours=time_to_fill))

# Main function
def main():
    parser = argparse.ArgumentParser(description="Smart Disk Monitor Plugin")
    parser.add_argument("-p", "--path", required=True, help="Path to monitor (e.g., / or C:\\)")
    parser.add_argument("-w", "--warning", type=int, required=True, help="Warning threshold for disk usage (%)")
    parser.add_argument("-c", "--critical", type=int, required=True, help="Critical threshold for disk usage (%)")
    parser.add_argument("-i", "--interval", type=int, default=24, help="Check interval in hours for prediction")

    args = parser.parse_args()

    # Get disk usage data
    disk_data = check_disk_usage(args.path)

    # Check for warning/critical thresholds
    status = "OK"
    if disk_data["percent"] >= args.critical:
        status = "CRITICAL"
    elif disk_data["percent"] >= args.warning:
        status = "WARNING"

    # Calculate usage delta (mock data for now, replace with historical data)
    usage_delta = 0.5  # Assume a mock growth rate of 0.5% per hour

    # Predict time to fill
    fill_prediction = predict_disk_fill(disk_data["percent"], usage_delta, args.interval)

    # Output result
    print(f"{status} - Disk usage at {disk_data['percent']}% | Total: {disk_data['total'] / (1024 ** 3):.2f}GB, Used: {disk_data['used'] / (1024 ** 3):.2f}GB, Free: {disk_data['free'] / (1024 ** 3):.2f}GB. Estimated time to full: {fill_prediction}")

    # Exit codes for Nagios
    if status == "CRITICAL":
        exit(2)
    elif status == "WARNING":
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    main()

import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from optparse import OptionParser

# Nagios states
STATE_OK = 0
STATE_CRITICAL = 2

# Default values
THRESHOLD = 40  # Default packet rate threshold
MAX_CHECK_ATTEMPTS = 3  # Maximum retries for SOFT states
check_attempts = defaultdict(int)  # Tracks the number of retries for each IP


def nagios_exit(state, message):
    """Exit with a Nagios-compatible status code and message."""
    print(message)
    sys.exit(state)


def handle_critical_state(ip, message):
    """Handles critical state for an IP."""
    print(message)
    os.system(f"iptables -A INPUT -s {ip} -j DROP")  # Block the offending IP
    nagios_exit(STATE_CRITICAL, message)


def packet_callback(packet):
    """Processes each packet to detect abnormal traffic."""
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                handle_critical_state(
                    ip, f"CRITICAL: Blocking IP {ip} with packet rate {packet_rate:.2f}/s"
                )
                blocked_ips.add(ip)
            else:
                print(f"OK: IP {ip} packet rate is normal at {packet_rate:.2f}/s")

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    # Ensure the script is run with root privileges
    if os.geteuid() != 0:
        nagios_exit(STATE_CRITICAL, "CRITICAL: This script requires root privileges.")

    # Parse command-line options
    parser = OptionParser("usage: %prog [options] -c <critical> -t <threshold>")
    parser.add_option("-c", "--critical", type="int", dest="crit", help="Critical threshold (max packet rate)")
    parser.add_option("-t", "--threshold", type="int", dest="threshold", help="Packet rate threshold (default: 40)")
    (opts, args) = parser.parse_args()

    if opts.crit is None:
        parser.error("Critical threshold (-c) is required. Example: -c 300")
        sys.exit(STATE_CRITICAL)

    if opts.threshold:
        THRESHOLD = opts.threshold

    # Initialize tracking variables
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print(f"Monitoring network traffic with a threshold of {THRESHOLD} packets/second...")
    try:
        sniff(filter="ip", prn=packet_callback)
    except KeyboardInterrupt:
        nagios_exit(STATE_OK, "OK: Monitoring stopped by user.")
    except Exception as e:
        nagios_exit(STATE_CRITICAL, f"CRITICAL: An error occurred - {str(e)}")

import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from optparse import OptionParser

__author__ = """
Author: Ayub Huruse
E-mail: your-email@example.com
Institution: Your Institution
"""

__version__ = "1.0.0"

# Define Nagios states
state_ok = 0
state_warning = 1
state_critical = 2

THRESHOLD = 40  # Default threshold


def nagios_exit(state, message):
    """Exit with a Nagios-compatible status code and message."""
    print(message)
    sys.exit(state)


def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    # Ensure the script is run with root privileges
    if os.geteuid() != 0:
        nagios_exit(state_critical, "CRITICAL: This script requires root privileges.")

    # Parse command-line options
    parser = OptionParser("usage: %prog [options] ARG1 ARG2 FOR EXAMPLE: -c 300 -w 200 -t 50")
    parser.add_option("-c", "--critical", type="int", dest="crit", help="The value to consider a very high connection in the web server")
    parser.add_option("-w", "--warning", type="int", dest="warn", help="The value to consider a high connection in the web server")
    parser.add_option("-t", "--threshold", type="int", dest="threshold", help="Set the packet rate threshold for blocking IPs")
    parser.add_option("-V", "--version", action="store_true", dest="version", help="Show the current version number of the program and exit")
    parser.add_option("-A", "--author", action="store_true", dest="author", help="Show author information and exit")
    (opts, args) = parser.parse_args()

    if opts.author:
        print(__author__)
        sys.exit()
    if opts.version:
        print(f"check_ddos.py {__version__}")
        sys.exit()

    if opts.crit and opts.warn:
        if opts.crit < opts.warn:
            print("Critical value < Warning value, please check your config")
            sys.exit(state_critical)
    else:
        parser.error("Please provide both -c and -w arguments. Example: -c 300 -w 200")
        sys.exit(state_critical)

    if opts.threshold:
        THRESHOLD = opts.threshold
    else:
        print(f"No threshold provided. Using default threshold: {THRESHOLD}")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print(f"Monitoring network traffic with a threshold of {THRESHOLD} packets/second...")
    try:
        sniff(filter="ip", prn=packet_callback)
    except KeyboardInterrupt:
        nagios_exit(state_ok, "OK: Monitoring stopped by user.")
    except Exception as e:
        nagios_exit(state_critical, f"CRITICAL: An error occurred - {str(e)}")

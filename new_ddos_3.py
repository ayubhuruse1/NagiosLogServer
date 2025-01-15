import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from optparse import OptionParser

state_ok = 0
state_warning = 1
state_critical = 2

def nagios_exit(state, message):
    """Exit with the appropriate Nagios state and message."""
    print(message)
    sys.exit(state)

def packet_callback(packet):
    """Callback function to process each packet."""
    try:
        src_ip = packet[IP].src
        packet_count[src_ip] += 1
    except Exception as e:
        nagios_exit(state_critical, f"CRITICAL: Error in packet processing - {str(e)}")

if __name__ == "__main__":
    parser = OptionParser("usage: %prog [options] ARG1 ARG2")
    parser.add_option("-c", "--critical", type="int", dest="crit", help="Critical threshold for packet rate")
    parser.add_option("-w", "--warning", type="int", dest="warn", help="Warning threshold for packet rate")
    parser.add_option("-t", "--threshold", type="int", dest="threshold", help="Packet rate threshold for DDoS detection")
    parser.add_option("-V", "--version", action="store_true", dest="version", help="Show version information and exit")
    parser.add_option("-A", "--author", action="store_true", dest="author", help="Show author information and exit")
    (opts, args) = parser.parse_args()

    if opts.author:
        print("Author: Ayub Huruse")
        sys.exit(state_ok)

    if opts.version:
        print("check_ddos.py version 1.1")
        sys.exit(state_ok)

    if not opts.crit or not opts.warn:
        nagios_exit(state_critical, "CRITICAL: Both -c and -w thresholds must be provided.")

    if opts.crit < opts.warn:
        nagios_exit(state_critical, "CRITICAL: Critical threshold cannot be lower than warning threshold.")

    THRESHOLD = opts.threshold if opts.threshold else 40
    print(f"Monitoring traffic with thresholds - Warning: {opts.warn}, Critical: {opts.crit}, Detection Threshold: {THRESHOLD}")

    try:
        packet_count = defaultdict(int)
        start_time = [time.time()]
        sniff(filter="ip", prn=packet_callback, store=0, timeout=10)  # Timeout after 10 seconds

        current_time = time.time()
        elapsed_time = current_time - start_time[0]
        rates = {ip: count / elapsed_time for ip, count in packet_count.items()}
        
        critical_ips = {ip: rate for ip, rate in rates.items() if rate > opts.crit}
        warning_ips = {ip: rate for ip, rate in rates.items() if opts.warn < rate <= opts.crit}
        
        if critical_ips:
            message = f"CRITICAL: High packet rate detected: {critical_ips} | packets_per_second={sum(critical_ips.values())}"
            nagios_exit(state_critical, message)
        elif warning_ips:
            message = f"WARNING: Moderate packet rate detected: {warning_ips} | packets_per_second={sum(warning_ips.values())}"
            nagios_exit(state_warning, message)
        else:
            nagios_exit(state_ok, "OK: No suspicious packet activity detected. | packets_per_second=0")

    except KeyboardInterrupt:
        nagios_exit(state_ok, "OK: Monitoring interrupted by user.")
    except Exception as e:
        nagios_exit(state_critical, f"CRITICAL: An error occurred - {str(e)}")

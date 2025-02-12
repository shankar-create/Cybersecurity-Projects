import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()

def packet_callback(packet):
    global packet_count, start_time, blocked_ips  

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count[src_ip] += 1

        current_time = time.time()
        time_interval = current_time - start_time[0]

        if time_interval >= 1:
            for ip, count in list(packet_count.items()):  
                packet_rate = count / time_interval

                if packet_rate > THRESHOLD and ip not in blocked_ips:
                    print(f"[ALERT] Blocking IP: {ip}, Packet rate: {packet_rate:.2f}")
                    os.system(f"iptables -A INPUT -s {ip} -j DROP")
                    blocked_ips.add(ip)

            packet_count.clear()  
            start_time[0] = current_time

if __name__ == "__main__":
    # Check if the script is running on Linux/macOS
    if os.name != "nt":  # 'nt' means Windows, so this runs only on Unix/Linux
        if os.geteuid() != 0:
            print("This script requires root privileges. Run with sudo.")
            sys.exit(1)
    else:
        print("[WARNING] Running on Windows: Root privilege check skipped.")

    print("[INFO] Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback, store=0)

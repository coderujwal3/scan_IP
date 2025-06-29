import socket
import ipaddress
from scapy.all import ARP, Ether, srp
from datetime import datetime

# get my default ip
def get_ip_range():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
    return str(network)

# function of scanning
def scan(ip_range):
    print(f"\n[*] Scanning IP range: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


# scan ip's
auto_ip_range = get_ip_range()
ip_ranges_to_scan = [auto_ip_range, "192.168.1.0/24", "192.168.56.0/24", "10.0.0.0/24", "137.97.225.0/24", "10.2.10.0/24", "10.2.12.0/24"]
ip_ranges_to_scan = list(set(ip_ranges_to_scan))  # Remove duplicates

all_devices = []

for ip_range in ip_ranges_to_scan:
    try:
        devices = scan(ip_range)
        all_devices.extend(devices)
    except Exception as e:
        print(f"[!] Failed to scan {ip_range}: {e}")

# output
log_lines = []
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
log_lines.append(f"\n[+] Scan completed at {timestamp}\n")
log_lines.append("-" * 40)

if all_devices:
    for device in all_devices:
        entry = f"IP: {device['ip']}, MAC: {device['mac']}"
        log_lines.append(entry)
else:
    log_lines.append("No active devices found.")

# prints scanning report to console 
for line in log_lines:
    print(line)

# log data to file
log_filename = "network_scan.log"
with open(log_filename, "a") as f:
    for line in log_lines:
        f.write(line + "\n")

print(f"\n[✔] Results exported to {log_filename}")

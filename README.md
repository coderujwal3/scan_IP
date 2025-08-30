# 🔍 Python Network Scanner
A simple Python-based network scanner that detects active devices on local and custom IP subnets using ARP requests. The results are printed to the console and logged in a `.log` file.

# ⚠️ Disclaimer
This tool is for educational and internal network scanning only. Unauthorized scanning of public networks or devices without consent is strictly prohibited and may violate laws or terms of service.

---

## 📌 Features

- Detects your local IP range automatically
- Scans multiple IP ranges (supports `/24` CIDR blocks)
- Identifies live hosts (IP + MAC addresses)
- Saves scan results with timestamps to `network_scan.log`

---

## 🧠 How It Works

- Uses **Scapy** to create ARP packets
- Broadcasts to all IPs in the given subnet
- Captures responses and extracts:
  - `IP address (psrc)`
  - `MAC address (hwsrc)`
- Handles multiple networks and avoids duplicates
- Logs all discovered devices with a timestamp

---

## 🛠️ Requirements

Ensure you have Python and the required modules:

```bash
pip install scapy
```
# 🧑‍💻 Author
Ujwal Singh
Feel free to reach out for collaboration or suggestions!

<img width="1920" height="1200" alt="Screenshot_2025-08-30_23_21_19" src="https://github.com/user-attachments/assets/fbfdc98d-b54b-4dc5-88d5-ae7a96aacc7b" />

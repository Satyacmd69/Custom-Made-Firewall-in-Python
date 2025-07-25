# 🔥 Custom Python Firewall 🔐  
A real-time, cross-platform firewall built in Python for monitoring, filtering, and blocking unwanted network traffic. Lightweight, GUI-based, and integrates with OS-level firewalls like `iptables` and `netsh`.

![Python Firewall](https://img.shields.io/badge/Python-3.8%2B-blue.svg) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg) ![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)

---

## 🛡️ Features

- 📡 **Real-Time Packet Sniffing**  
  Monitor incoming/outgoing packets using **Scapy**

- 🔒 **Port & Protocol Blocking**  
  Block specific ports, protocols (TCP/UDP), or IP addresses

- ⚙️ **OS Integration**  
  Works with system firewalls:  
  - Linux → `iptables`  
  - Windows → `netsh`

- 💻 **Interactive GUI**  
  Built with `tkinter` (or `PyQt`) for easy access to controls and logs

- 📁 **Dynamic Rule Loader**  
  Uses `rules.json` to configure blocked IPs, ports, and protocols

- 📊 **Logging System**  
  Displays logs of all blocked/suspicious packets in real-time

---

## 📂 Project Structure
```
python-firewall/
├── firewall/
│ ├── init.py
│ ├── sniff.py # Packet sniffing
│ ├── blocker.py # Rule handler + OS-level commands
│ ├── gui.py # tkinter GUI
│ └── logger.py # Logs blocked packets
├── rules.json # Editable rule file
├── main.py # Entry point
├── requirements.txt
└── README.md
```

---

## 🛠️ Installation & Usage

### 🔗 Prerequisites

- Python 3.8+
- Scapy
- Admin/root privileges (for firewall rules)
- tkinter or PyQt5

### ⚙️ Installation

```bash
git clone https://github.com/Satyacmd69/python-firewall.git
cd python-firewall
pip install -r requirements.txt

```bash
🚀 Run the Firewall

sudo python3 main.py  # Linux (root access required)
# OR
python main.py        # Windows (run as admin)

```

---
🧩 Configure Rules
Edit rules.json:
    {
  "block_ports": [21, 23, 4444],
  "block_ips": ["192.168.1.100"],
  "block_protocols": ["TCP", "UDP"]
    }
---

✅ Tested On :- 
✅ Kali Linux
✅ Ubuntu 22.04
✅ Windows 10/11 (Admin Mode)

📜 License
This project is licensed under the MIT License.
Feel free to use, modify, and distribute.

🤝 Connect With Me
💼 LinkedIn
🧠 Portfolio/Blog
🐍 Python + Security Enthusiast

Star ⭐ this project if you like it!
Fork 🍴 it to build your own version!
Watch 👀 to stay updated!


---

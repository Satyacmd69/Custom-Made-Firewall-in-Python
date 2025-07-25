import subprocess
import platform

def block_ip(ip):
    system = platform.system()
    if system == "Windows":
        subprocess.run(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}", shell=True)
    elif system == "Linux":
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)

def unblock_ip(ip):
    system = platform.system()
    if system == "Windows":
        subprocess.run(f"netsh advfirewall firewall delete rule name=\"Block {ip}\"", shell=True)
    elif system == "Linux":
        subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)

import platform
import subprocess
import sys
from firewall import gui_tkinter
from firewall.packet_sniffer import start_sniffing
from firewall.os_firewall import block_ip, unblock_ip
import os
import json

RULES_PATH = os.path.join("firewall", "rules.json")
LOG_PATH = os.path.join("logs", "firewall.log")

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def load_rules():
    with open(RULES_PATH, "r") as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=4)

def block_ip_cli():
    ip = input("Enter IP to block: ").strip()
    rules = load_rules()
    if ip not in rules["blocked_ips"]:
        rules["blocked_ips"].append(ip)
        save_rules(rules)
        block_ip(ip)
        print(f"[✔] IP {ip} blocked at both app and system level.")
    else:
        print(f"[!] IP {ip} is already blocked.")

def unblock_ip_cli():
    ip = input("Enter IP to unblock: ").strip()
    rules = load_rules()
    if ip in rules["blocked_ips"]:
        rules["blocked_ips"].remove(ip)
        save_rules(rules)
        unblock_ip(ip)
        print(f"[✔] IP {ip} unblocked from both app and system level.")
    else:
        print(f"[!] IP {ip} was not in block list.")

def show_logs():
    if not os.path.exists(LOG_PATH):
        print("[!] Log file not found.")
        return

    with open(LOG_PATH, "r") as f:
        logs = f.read()
        if logs.strip():
            print("\n====== FIREWALL LOGS ======")
            print(logs)
        else:
            print("[*] No logs available.")

def main():
    while True:
        clear()
        print("🛡️  Python Advanced Firewall Launcher")
        print("------------------------------------")
        print("1. Launch Firewall GUI")
        print("2. Start Packet Sniffer")
        print("3. Block IP (CLI)")
        print("4. Unblock IP (CLI)")
        print("5. Show Logs")
        print("6. Exit")

        choice = input("\nSelect an option (1-6): ").strip()

        if choice == "1":
            print("[*] Launching GUI...")
            gui_tkinter.root.mainloop()

        elif choice == "2":
            print("[*] Starting Packet Sniffer (Ctrl+C to stop)...")
            try:
                start_sniffing()
            except KeyboardInterrupt:
                print("\n[!] Sniffing stopped by user.")

        elif choice == "3":
            block_ip_cli()
            input("Press Enter to return to menu...")

        elif choice == "4":
            unblock_ip_cli()
            input("Press Enter to return to menu...")

        elif choice == "5":
            show_logs()
            input("\nPress Enter to return to menu...")

        elif choice == "6":
            print("[*] Exiting firewall launcher.")
            sys.exit(0)

        else:
            print("[!] Invalid option. Try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()

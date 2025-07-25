import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import json
import os
import sys

# Allow imports from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from firewall.os_firewall import block_ip, unblock_ip

RULES_PATH = os.path.join("firewall", "rules.json")
LOG_PATH = os.path.join("logs", "firewall.log")


def load_rules():
    with open(RULES_PATH, "r") as f:
        return json.load(f)


def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=4)


class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Python Firewall Manager")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", font=("Segoe UI", 10))
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"))

        self.tab_control = ttk.Notebook(self.root)
        self.create_block_tab()
        self.create_unblock_tab()
        self.create_logs_tab()
        self.tab_control.pack(expand=1, fill="both")

        self.tab_control.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def create_block_tab(self):
        self.block_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.block_tab, text="Block IP")

        label = ttk.Label(self.block_tab, text="Enter IP to Block:", font=("Segoe UI", 12))
        label.pack(pady=10)

        self.block_ip_entry = ttk.Entry(self.block_tab, width=40)
        self.block_ip_entry.pack(pady=5)

        block_button = ttk.Button(self.block_tab, text="Block IP", command=self.block_ip_action)
        block_button.pack(pady=10)

        self.block_status = ttk.Label(self.block_tab, text="", foreground="green", font=("Segoe UI", 10))
        self.block_status.pack()

        ttk.Label(self.block_tab, text="Currently Blocked IPs:", font=("Segoe UI", 11, "bold")).pack(pady=15)

        self.blocked_listbox = tk.Listbox(self.block_tab, height=8, width=50, font=("Consolas", 10))
        self.blocked_listbox.pack()
        self.refresh_blocked_list()

    def refresh_blocked_list(self):
        rules = load_rules()
        blocked_ips = rules.get("blocked_ips", [])

        self.blocked_listbox.delete(0, tk.END)
        for ip in blocked_ips:
            self.blocked_listbox.insert(tk.END, ip)

    def block_ip_action(self):
        ip = self.block_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")
            return

        rules = load_rules()
        if ip in rules["blocked_ips"]:
            self.block_status.config(text=f"IP {ip} is already blocked.", foreground="orange")
        else:
            rules["blocked_ips"].append(ip)
            save_rules(rules)
            block_ip(ip)
            self.block_status.config(text=f"IP {ip} blocked successfully.", foreground="green")
            self.refresh_blocked_list()
            self.append_log(f"[GUI] Blocked IP: {ip}")

    def create_unblock_tab(self):
        self.unblock_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.unblock_tab, text="Unblock IP")

        label = ttk.Label(self.unblock_tab, text="Enter IP to Unblock:", font=("Segoe UI", 12))
        label.pack(pady=10)

        self.unblock_ip_entry = ttk.Entry(self.unblock_tab, width=40)
        self.unblock_ip_entry.pack(pady=5)

        unblock_button = ttk.Button(self.unblock_tab, text="Unblock IP", command=self.unblock_ip_action)
        unblock_button.pack(pady=10)

        self.unblock_status = ttk.Label(self.unblock_tab, text="", foreground="green", font=("Segoe UI", 10))
        self.unblock_status.pack()

    def unblock_ip_action(self):
        ip = self.unblock_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")
            return

        rules = load_rules()
        if ip in rules["blocked_ips"]:
            rules["blocked_ips"].remove(ip)
            save_rules(rules)
            unblock_ip(ip)
            self.unblock_status.config(text=f"IP {ip} unblocked.", foreground="green")
            self.refresh_blocked_list()
            self.append_log(f"[GUI] Unblocked IP: {ip}")
        else:
            self.unblock_status.config(text=f"IP {ip} is not blocked.", foreground="orange")

    def create_logs_tab(self):
        self.logs_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.logs_tab, text="View Logs")

        label = ttk.Label(self.logs_tab, text="Firewall Logs:", font=("Segoe UI", 12, "bold"))
        label.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(self.logs_tab, width=95, height=28, font=("Courier", 10))
        self.log_area.pack(padx=10)

        refresh_btn = ttk.Button(self.logs_tab, text="🔄 Refresh Logs", command=self.load_logs)
        refresh_btn.pack(pady=10)

    def load_logs(self):
        self.log_area.delete("1.0", tk.END)
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                content = f.read()
                self.log_area.insert(tk.END, content)
        else:
            self.log_area.insert(tk.END, "[!] Log file not found.")

    def append_log(self, message):
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} {message}\n"
        with open(LOG_PATH, "a") as f:
            f.write(line)

    def on_tab_changed(self, event):
        current_tab = event.widget.tab(event.widget.index("current"))["text"]
        if current_tab == "View Logs":
            self.load_logs()


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()

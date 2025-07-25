from scapy.all import sniff, IP, TCP, UDP
import json

def load_rules():
    with open("firewall/rules.json") as f:
        return json.load(f)

def inspect_packet(packet):
    rules = load_rules()

    if IP in packet:
        ip_src = packet[IP].src
        proto = packet.proto
        if ip_src in rules["blocked_ips"]:
            print(f"[BLOCKED] Packet from {ip_src}")
            return

    if TCP in packet and "block_tcp_ports" in rules:
        port = packet[TCP].dport
        if port in rules["block_tcp_ports"]:
            print(f"[BLOCKED] TCP Port {port} access")
            return

    if UDP in packet and "block_udp_ports" in rules:
        port = packet[UDP].dport
        if port in rules["block_udp_ports"]:
            print(f"[BLOCKED] UDP Port {port} access")
            return

    print(f"[ALLOWED] Packet from {packet[IP].src} to {packet[IP].dst}")

def start_sniffing():
    print("[*] Starting packet sniffing on all interfaces...")
    sniff(prn=inspect_packet, store=False)

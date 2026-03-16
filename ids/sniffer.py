from scapy.all import sniff, IP, TCP, UDP, ARP
from ids.detector import analyze_packet

def packet_callback(packet):
    # Send every packet to the detection engine
    alerts = analyze_packet(packet)

    for alert in alerts:
        print(f"[!] ALERT: {alert['attack_type']} from {alert['source_ip']} — {alert['details']}")

    # Optional: still print packet summary for debugging
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"[IP] {src_ip} → {dst_ip}")

        if TCP in packet:
            flags = packet[TCP].flags
            print(f"  [TCP] {packet[TCP].sport} → {packet[TCP].dport} | flags: {flags}")

    elif ARP in packet:
        print(f"  [ARP] {packet[ARP].psrc} is at {packet[ARP].hwsrc}")

def start_sniffing(interface=None):
    print(f"[*] Starting sniffer on interface: {interface or 'default'}")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False
    )

if __name__ == "__main__":
    start_sniffing()
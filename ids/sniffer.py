from scapy.all import sniff, IP, TCP, UDP, ARP, conf
from ids.detector import analyze_packet
from ids.alerts import trigger_alert, init_db
from ids.metrics import record_alert, start_metrics_server

conf.use_pcap = True

def packet_callback(packet):
    alerts = analyze_packet(packet)

    for alert in alerts:
        trigger_alert(alert)
        record_alert(alert)                           

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
    init_db()
    start_metrics_server()
    print(f"[*] Starting sniffer on interface: {interface or 'default'}")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False
    )

if __name__ == "__main__":
    start_sniffing()
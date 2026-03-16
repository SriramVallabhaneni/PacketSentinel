from scapy.all import sniff, IP, TCP, UDP, ARP

def packet_callback(packet):
    
    # only process if packets have IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"[IP] {src_ip} → {dst_ip} | protocol: {protocol}")

        # TCP packet
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"  [TCP] {src_port} → {dst_port} | flags: {flags}")

        # UDP packet
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  [UDP] {src_port} → {dst_port}")

    # ARP packet (has no IP layer, lives at layer 2)
    elif ARP in packet:
        print(f"  [ARP] {packet[ARP].psrc} is at {packet[ARP].hwsrc}")


def start_sniffing(interface="eth0"):
    print(f"[*] Starting sniffer on interface: {interface or 'default'}")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False        # don't store packets in memory
    )

if __name__ == "__main__":
    start_sniffing()
from scapy.all import IP, TCP, ARP, Ether, sendp
import time

TARGET_IP = "172.20.160.1"    # your gateway IP from the ARP output
YOUR_IP = "172.20.171.71"     # your machine's IP
IFACE = "eth0"                # your interface

def simulate_syn_flood():
    """Send 110 SYN packets to port 80 — should trigger SYN_FLOOD"""
    print("[*] Simulating SYN flood...")
    for _ in range(110):
        pkt = IP(src="10.0.0.2", dst=TARGET_IP) / TCP(dport=80, flags="S")
        sendp(Ether()/pkt, iface=IFACE, verbose=False)
    print("[*] SYN flood done")


if __name__ == "__main__":
    simulate_syn_flood()
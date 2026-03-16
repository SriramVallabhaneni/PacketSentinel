from scapy.all import IP, TCP, ARP, Ether, sendp
import time

TARGET_IP = "172.20.160.1"    # your gateway IP from the ARP output
YOUR_IP = "172.20.171.71"     # your machine's IP
IFACE = "eth0"                # your interface

def simulate_port_scan():
    """Send SYN packets to 30 different ports — should trigger PORT_SCAN"""
    print("[*] Simulating port scan...")
    for port in range(1, 31):
        pkt = IP(src="10.0.0.1", dst=TARGET_IP) / TCP(dport=port, flags="S")
        sendp(Ether()/pkt, iface=IFACE, verbose=False)
    print("[*] Port scan done")

if __name__ == "__main__":
    simulate_port_scan()
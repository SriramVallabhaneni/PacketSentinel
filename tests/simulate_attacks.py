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

def simulate_syn_flood():
    """Send 110 SYN packets to port 80 — should trigger SYN_FLOOD"""
    print("[*] Simulating SYN flood...")
    for _ in range(110):
        pkt = IP(src="10.0.0.2", dst=TARGET_IP) / TCP(dport=80, flags="S")
        sendp(Ether()/pkt, iface=IFACE, verbose=False)
    print("[*] SYN flood done")

def simulate_arp_spoof():
    """
    Send ARP reply claiming a known IP has a different MAC
    should trigger ARP_SPOOF
    """
    print("[*] Simulating ARP spoof...")

    # First packet — establish a legitimate mapping
    legit = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                           # op=2 means ARP reply
        psrc=TARGET_IP,
        hwsrc="00:11:22:33:44:55"       # fake "legitimate" MAC
    )
    sendp(legit, iface=IFACE, verbose=False)
    time.sleep(0.5)

    # Second packet — same IP, different MAC (the spoof)
    spoof = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=TARGET_IP,
        hwsrc="aa:bb:cc:dd:ee:ff"       # different MAC = spoof detected
    )
    sendp(spoof, iface=IFACE, verbose=False)
    print("[*] ARP spoof done")

if __name__ == "__main__":
    simulate_port_scan()
    time.sleep(1)
    simulate_syn_flood()
    time.sleep(1)
    simulate_arp_spoof()
from scapy.all import IP, TCP, ARP, Ether, sendp
import time

TARGET_IP = "172.20.160.1"    # your gateway IP from the ARP output
YOUR_IP = "172.20.171.71"     # your machine's IP
IFACE = "eth0"                # your interface

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
    simulate_arp_spoof()
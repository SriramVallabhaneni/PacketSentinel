from collections import defaultdict
import time

# Thresholds
# IDEALLY: THRESHOLDS should probably be configured based on NORMAL NETWORK PATTERNS, rather than hard numbers.
PORT_SCAN_THRESHOLD = 20      # unique ports in time window
SYN_FLOOD_THRESHOLD = 100     # SYN packets in time window
TIME_WINDOW = 5               # seconds

# State tracking

# Port scan: track which ports each source IP has hit
# { src_ip: [(timestamp, dst_port), ...] }
port_scan_tracker = defaultdict(list)

# SYN flood: track SYN packet count per source IP
# { src_ip: [timestamp, ...] }
syn_flood_tracker = defaultdict(list)

# ARP spoof: track known IP → MAC mappings
# { ip: mac }
arp_table = {}


# ─── Helpers ──────────────────────────────────────────────

def get_recent(entries, now):
    """Filter entries to only those within the time window."""
    return [t for t in entries if now - t < TIME_WINDOW]


# ─── Detection Rules ──────────────────────────────────────

def detect_port_scan(src_ip, dst_port, flags, now):
    """
    Attacker sends SYN packets to many different ports.
    We track unique destination ports per source IP.
    """
    if "S" not in str(flags):
        return None

    tracker = port_scan_tracker[src_ip]

    # Keep only recent (timestamp, port) entries
    recent = [(t, p) for t, p in tracker if now - t < TIME_WINDOW]
    recent.append((now, dst_port))
    port_scan_tracker[src_ip] = recent

    unique_ports = set(p for _, p in recent)

    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        return {
            "attack_type": "PORT_SCAN",
            "source_ip": src_ip,
            "details": f"{len(unique_ports)} unique ports scanned in {TIME_WINDOW}s"
        }
    return None


def detect_syn_flood(src_ip, dst_ip, flags, now):
    """
    Attacker sends massive SYN packets to overwhelm a target.
    We track SYN rate per source IP.
    """
    if "S" not in str(flags):
        return None

    tracker = syn_flood_tracker[src_ip]
    recent = get_recent(tracker, now)
    recent.append(now)
    syn_flood_tracker[src_ip] = recent

    if len(recent) > SYN_FLOOD_THRESHOLD:
        return {
            "attack_type": "SYN_FLOOD",
            "source_ip": src_ip,
            "details": f"{len(recent)} SYN packets in {TIME_WINDOW}s targeting {dst_ip}"
        }
    return None


def detect_arp_spoof(src_ip, src_mac):
    """
    Attacker sends ARP replies claiming to be a legitimate IP.
    We detect when an IP's MAC address changes unexpectedly.
    """
    if src_ip in arp_table:
        known_mac = arp_table[src_ip]
        if known_mac != src_mac:
            return {
                "attack_type": "ARP_SPOOF",
                "source_ip": src_ip,
                "details": f"MAC changed from {known_mac} to {src_mac}"
            }
    else:
        # First time seeing this IP, just record it
        arp_table[src_ip] = src_mac

    return None


# ─── Main entry point ─────────────────────────────────────

def analyze_packet(packet):
    """
    Called for every packet. Routes to the right detectors
    and returns a list of any alerts triggered.
    """
    from scapy.all import IP, TCP, ARP

    alerts = []
    now = time.time()

    # TCP based detections
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        alert = detect_port_scan(src_ip, dst_port, flags, now)
        if alert:
            alerts.append(alert)

        alert = detect_syn_flood(src_ip, dst_ip, flags, now)
        if alert:
            alerts.append(alert)

    # ARP based detection
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        alert = detect_arp_spoof(src_ip, src_mac)
        if alert:
            alerts.append(alert)

    return alerts
from prometheus_client import Counter, Gauge, start_http_server
import time

# ─── Metrics definitions ──────────────────────────────────
port_scan_counter = Counter(
    "ids_port_scans_total",
    "Total number of port scan attempts detected",
    ["source_ip"]
)

syn_flood_counter = Counter(
    "ids_syn_floods_total",
    "Total number of SYN flood attempts detected",
    ["source_ip"]
)

arp_spoof_counter = Counter(
    "ids_arp_spoof_attempts_total",
    "Total number of ARP spoofing attempts detected",
    ["source_ip"]
)

alerts_total = Counter(
    "ids_alerts_total",
    "Total number of alerts triggered across all attack types",
    ["attack_type"]
)

active_attackers = Gauge(
    "ids_active_attackers",
    "Number of unique source IPs that triggered alerts in last 60s"
)

# ─── Active attacker tracking ─────────────────────────────
_active_attacker_timestamps = {}
ACTIVE_WINDOW = 60

def _update_active_attackers(src_ip):
    now = time.time()
    _active_attacker_timestamps[src_ip] = now
    active = sum(1 for t in _active_attacker_timestamps.values() if now - t < ACTIVE_WINDOW)
    active_attackers.set(active)

# ─── Main update function ─────────────────────────────────
def record_alert(alert: dict):
    attack_type = alert["attack_type"]
    src_ip      = alert["source_ip"]

    if attack_type == "PORT_SCAN":
        port_scan_counter.labels(source_ip=src_ip).inc()
    elif attack_type == "SYN_FLOOD":
        syn_flood_counter.labels(source_ip=src_ip).inc()
    elif attack_type == "ARP_SPOOF":
        arp_spoof_counter.labels(source_ip=src_ip).inc()

    alerts_total.labels(attack_type=attack_type).inc()
    _update_active_attackers(src_ip)

# ─── HTTP server ──────────────────────────────────────────
def start_metrics_server(port=8000):
    start_http_server(port)
    print(f"[*] Metrics server started at http://localhost:{port}/metrics")
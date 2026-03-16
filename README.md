# Python Network Intrusion Detection System

A Python-based network intrusion detection system (IDS) that monitors live traffic, detects common attacks, and visualizes security metrics through a Grafana dashboard backed by Prometheus.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green)
![Prometheus](https://img.shields.io/badge/Prometheus-latest-orange)
![Grafana](https://img.shields.io/badge/Grafana-latest-red)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)

---

## Features

- **Live packet capture** using Scapy
- **Attack detection** for three common attack types:
  - Port scanning (SYN burst to many ports)
  - SYN flood (DoS via high SYN packet rate)
  - ARP spoofing (MITM via ARP poisoning)
- **Alert system** with structured logging and SQLite persistence
- **Prometheus metrics** exposed at `http://localhost:8000/metrics`
- **Grafana dashboard** with real-time attack visualization
- **Cooldown system** to suppress duplicate alerts per IP

---

## Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy)
      ↓
Detection Engine
      ↓
Alert System (logs + SQLite)
      ↓
Metrics Exporter (Prometheus)
      ↓
Grafana Dashboard
```

---

## Detection Rules

| Attack | Method | Threshold |
|---|---|---|
| Port Scan | SYN packets to >20 unique ports in 5s | 20 ports |
| SYN Flood | >100 SYN packets to same target in 5s | 100 packets |
| ARP Spoof | IP→MAC mapping changes unexpectedly | Any change |

Thresholds are configurable in `ids/detector.py`. In production these should be tuned based on your network's normal baseline traffic.

---

## A Note on How This Project Runs

The IDS app requires **raw network socket access** to capture packets at the network interface level. This means it must run natively on the host machine with root privileges. I am currently unable to fully containerized in the current setup.

Docker is used here for **Prometheus and Grafana only**. The IDS app runs natively alongside the Docker stack.

This is a deliberate architectural decision: raw packet capture requires direct access to the host network interface, which Docker's network isolation seems to prevents on my current platform (WSL2). On WSL2 and Windows, `network_mode: host` does not expose the real host network interface. It exposes the Hyper-V VM's interface instead, making packet capture of real traffic impossible.

The `Dockerfile` is included in the repo for completeness and works correctly on a real Linux machine or VM if you choose to build and run the container manually.

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/python-ids.git
cd python-ids
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start Prometheus and Grafana

```bash
docker compose up -d
```

### 4. Start the IDS app

```bash
# Requires sudo for raw packet capture
sudo venv/bin/python3 -m ids.sniffer
```

You should see:
```
[*] Metrics server started at http://localhost:8000/metrics
[*] Starting sniffer on interface: default
```

---

## Grafana Dashboard

1. Open `http://localhost:3000`
2. Login with `admin / admin`
3. Go to **Dashboards** → **New** → **Import**
4. Upload `dashboards/ids_dashboard.json`
5. Select **Prometheus** as the datasource
6. Click **Import**

Dashboard panels:
- Alert rate over time (time series)
- Total alerts (stat)
- Active attackers (stat)
- Alerts by attack type (stat)
- Port scans by source IP (bar chart)
- SYN floods by source IP (bar chart)
- ARP spoof attempts by source IP (bar chart)

---

## Simulating Attacks

Run these while the sniffer is active in another terminal.

```bash
# Port scan
sudo venv/bin/python3 tests/simulate_port_scan.py

# SYN flood
sudo venv/bin/python3 tests/simulate_syn_flood.py

# ARP spoof
sudo venv/bin/python3 tests/simulate_arp_spoof.py

```

### Real attacks (requires Kali Linux VM)

| Attack | Tool | Command |
|---|---|---|
| Port scan | nmap | `nmap -sS <target_ip>` |
| SYN flood | hping3 | `hping3 -S --flood -p 80 <target_ip>` |
| ARP spoof | ettercap | `ettercap -T -M arp:remote /<victim>/ /<gateway>/` |

---

## Checking Alerts

```bash
# View log file
cat logs/alerts.log

# Query SQLite database
sqlite3 data/alerts.db "SELECT * FROM alerts;"

# View Prometheus metrics
curl http://localhost:8000/metrics | grep ids_
```

---

## Configuration

Edit thresholds in `ids/detector.py`:

```python
# IDEALLY: THRESHOLDS should probably be configured based on NORMAL NETWORK PATTERNS, rather than hard numbers.
PORT_SCAN_THRESHOLD = 20    # unique ports in time window
SYN_FLOOD_THRESHOLD = 100   # SYN packets in time window
TIME_WINDOW = 5             # seconds
COOLDOWN = 10               # seconds before same IP can alert again
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet capture | Scapy |
| Alert storage | SQLite + Python logging |
| Metrics | Prometheus client |
| Visualization | Grafana |
| Containerization | Docker Compose |

---

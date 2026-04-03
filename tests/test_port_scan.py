import time
import pytest
from ids.detector import detect_port_scan, port_scan_tracker, cooldown_tracker

def setup_function():
    """Clear state before each test."""
    port_scan_tracker.clear()
    cooldown_tracker.clear()

def test_no_alert_below_threshold():
    now = time.time()
    for port in range(1, 15):
        result = detect_port_scan("10.0.0.1", port, "S", now)
    assert result is None

def test_alert_above_threshold():
    now = time.time()
    result = None
    for port in range(1, 25):
        result = detect_port_scan("10.0.0.1", port, "S", now)
    assert result is not None
    assert result["attack_type"] == "PORT_SCAN"
    assert result["source_ip"] == "10.0.0.1"

def test_no_alert_for_non_syn():
    now = time.time()
    result = None
    for port in range(1, 25):
        result = detect_port_scan("10.0.0.1", port, "A", now)
    assert result is None

def test_cooldown_prevents_duplicate():
    now = time.time()
    for port in range(1, 25):
        detect_port_scan("10.0.0.1", port, "S", now)
    result = detect_port_scan("10.0.0.1", 999, "S", now)
    assert result is None
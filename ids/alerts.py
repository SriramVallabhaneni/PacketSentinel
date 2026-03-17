import sqlite3
import logging
import json
import os
from datetime import datetime

# ─── Paths ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")
DB_FILE  = os.path.join(BASE_DIR, "data", "alerts.db")

# ─── Logger setup ─────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─── Database setup ───────────────────────────────────────
def init_db():
    """Create the alerts table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            attack_type TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            details     TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# ─── Core alert function ──────────────────────────────────
def trigger_alert(alert: dict):
    """
    Receives an alert dict from the detector and:
    1. Adds a timestamp
    2. Prints to terminal
    3. Writes to log file
    4. Stores in SQLite
    """
    # 1. Stamp it
    alert["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # 2. Terminal
    print(
        f"[!] {alert['timestamp']} | "
        f"{alert['attack_type']} | "
        f"{alert['source_ip']} | "
        f"{alert['details']}"
    )

    # 3. Log file
    logger.warning(json.dumps(alert))

    # 4. SQLite
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, attack_type, source_ip, details)
            VALUES (?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["attack_type"],
            alert["source_ip"],
            alert["details"]
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
    finally:
        conn.close()


# ─── Query helpers (useful for dashboard later) ───────────
def get_recent_alerts(limit=20):
    """Fetch the most recent alerts from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, attack_type, source_ip, details
        FROM alerts
	GROUP BY attack_type, source_ip
        ORDER BY MAX(id) DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_alert_counts():
    """Get total count per attack type."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM alerts
        GROUP BY attack_type
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

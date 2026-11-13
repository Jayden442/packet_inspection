import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "nids.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                description TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_packets INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                unique_source_ips INTEGER NOT NULL,
                TCP_connections INTEGER NOT NULL,
                UDP_connections INTEGER NOT NULL,
                ICMP_connections INTEGER NOT NULL,
                DNS_queries INTEGER NOT NULL
            )
        """)

        conn.execute("PRAGMA journal_mode=WAL")

def save_alert(alert):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alerts (timestamp, alert_type, severity, source_ip, destination_ip, description, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.timestamp.isoformat(),
            alert.alert_type,
            alert.severity.name,
            alert.source_ip,
            alert.destination_ip,
            alert.description,
            int(alert.acknowledged)
        ))

def get_alerts(limit=100, severity=None, alert_type=None, acknowledged=None):
    with get_connection() as conn:
        query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
        params = [limit]

        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)

        if alert_type is not None:
            query += " AND alert_type = ?"
            params.append(alert_type)

        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(int(acknowledged))

        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def change_alert_acknowledgement(alert_id, acknowledge=True):
    with get_connection() as conn:
        conn.execute("""
            UPDATE alerts
            SET acknowledged = ?
            WHERE id = ?
        """, (int(acknowledge), alert_id))
        return conn.rowcount > 0  # Returns True if an alert was updated, False otherwise

def save_traffic_statistics(statistics):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO traffic_statistics (timestamp, total_packets, total_bytes, unique_source_ips, TCP_connections, UDP_connections, ICMP_connections, DNS_queries)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            statistics.timestamp.isoformat(),
            statistics.total_packets,
            statistics.total_bytes,
            statistics.unique_source_ips,
            statistics.TCP_connections,
            statistics.UDP_connections,
            statistics.ICMP_connections,
            statistics.DNS_queries
        ))
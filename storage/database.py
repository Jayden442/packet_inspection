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
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,

                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,

                tcp_packets INTEGER DEFAULT 0,
                udp_packets INTEGER DEFAULT 0,
                icmp_packets INTEGER DEFAULT 0,

                unique_source_ips INTEGER DEFAULT 0,
                unique_destination_ips INTEGER DEFAULT 0,

                syn_packets INTEGER DEFAULT 0,
                dns_queries INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_statistics_timestamp
            ON statistics(timestamp);
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

def save_statistics(statistics):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO statistics (
                timestamp, interval_seconds, total_packets, total_bytes,
                tcp_packets, udp_packets, icmp_packets,
                unique_source_ips, unique_destination_ips,
                syn_packets, dns_queries
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            statistics.timestamp.isoformat(),
            statistics.interval_seconds,
            statistics.total_packets,
            statistics.total_bytes,
            statistics.tcp_packets,
            statistics.udp_packets,
            statistics.icmp_packets,
            statistics.unique_source_ips,
            statistics.unique_destination_ips,
            statistics.syn_packets,
            statistics.dns_queries
        ))
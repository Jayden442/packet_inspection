import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "nids.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    print("Database path:", DB_PATH.resolve(), flush=True)
    print("Database directory exists:", DB_PATH.parent.exists(), flush=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():
    with get_connection() as conn:
        print("initializing")
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

                syn_packets INTEGER DEFAULT 0,
                dns_queries INTEGER DEFAULT 0
            );
        """)

        conn.execute("""
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

def get_alerts(limit=100, severity=None, alert_type=None, acknowledged=None, start=None, end=None):
    
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
    if start is not None:
        query += " AND timestamp >= ?"
        params.append(start)
    if end is not None:
        query += " AND timestamp <= ?"
        params.append(end)
    with get_connection() as conn:
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

def get_alert_by_id(alert_id):
    with get_connection() as conn:
        row = conn.execute("""
        SELECT *
        FROM alerts
        WHERE id = ?        
        """, (alert_id,)).fetchone()
        return dict(row) if row else None

def get_statistics_timeframe(start, end, limit=250):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM statistics
            WHERE timestamp >= ?
            AND timestamp <= ?
            ORDER BY timestamp ASC
            LIMIT ?
            """, (start, end, limit)).fetchall()
        return [dict(row) for row in rows]

def get_statistics_summary(start, end):
    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                COALESCE(SUM(total_packets), 0) AS total_packets,
                COALESCE(SUM(total_bytes), 0) AS total_bytes,
                COALESCE(SUM(tcp_packets), 0) AS tcp_packets,
                COALESCE(SUM(udp_packets), 0) AS udp_packets,
                COALESCE(SUM(icmp_packets), 0) AS icmp_packets,
                COALESCE(SUM(syn_packets), 0) AS syn_packets,
                COALESCE(SUM(dns_queries), 0) AS dns_queries
            FROM statistics
            WHERE timestamp >= ?
            AND timestamp <= ?
        """, (start, end)).fetchone()
        return dict(row)

def save_statistics(snapshot):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO statistics (
                timestamp, interval_seconds, total_packets, total_bytes,
                tcp_packets, udp_packets, icmp_packets,
                syn_packets, dns_queries
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot["timestamp"],
            snapshot["interval_seconds"],
            snapshot["total_packets"],
            snapshot["total_bytes"],
            snapshot["tcp_packets"],
            snapshot["udp_packets"],
            snapshot["icmp_packets"],
            snapshot["syn_packets"],
            snapshot["dns_queries"]
        ))
from datetime import datetime, timedelta, timezone
from storage.database import get_connection


def cleanup_old_records():
    now = datetime.now(timezone.utc)

    alert_cutoff = (
        now - timedelta(days=90)
    ).isoformat()

    statistics_cutoff = (
        now - timedelta(days=90)
    ).isoformat()

    with get_connection() as conn:
        # Delete old acknowledged alerts
        conn.execute("""
            DELETE FROM alerts
            WHERE timestamp < ?
            AND acknowledged = 1
        """, (alert_cutoff,))

        # Delete old historical statistics
        conn.execute("""
            DELETE FROM statistics
            WHERE timestamp < ?
        """, (statistics_cutoff,))
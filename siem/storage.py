# siem/storage.py

import os
import sqlite3
from typing import Optional, List, Dict

from .models import Event, Alert

# place DB inside Watchtower/data
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "siem.db"
)


class SQLiteStorage:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def init_db(self) -> None:
        assert self.conn is not None
        cur = self.conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                raw TEXT,
                action TEXT,
                user TEXT,
                src_ip TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                rule_name TEXT,
                severity TEXT,
                src_ip TEXT,
                user TEXT,
                message TEXT
            )
            """
        )

        self.conn.commit()

    def insert_event(self, event: Event) -> int:
        assert self.conn is not None
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO events (timestamp, source, raw, action, user, src_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source,
                event.raw,
                event.action,
                event.user,
                event.src_ip,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_alert(self, alert: Alert) -> int:
        assert self.conn is not None
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (timestamp, rule_name, severity, src_ip, user, message)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert.timestamp,
                alert.rule_name,
                alert.severity,
                alert.src_ip,
                alert.user,
                alert.message,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def fetch_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict]:
        """
        Return alerts as a list of dictionaries, optional severity filter.
        """
        assert self.conn is not None
        cur = self.conn.cursor()

        if severity:
            cur.execute(
                """
                SELECT timestamp, rule_name, severity, src_ip, user, message
                FROM alerts
                WHERE LOWER(severity) = LOWER(?)
                ORDER BY id DESC
                LIMIT ?
                """,
                (severity, limit),
            )
        else:
            cur.execute(
                """
                SELECT timestamp, rule_name, severity, src_ip, user, message
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )

        rows = cur.fetchall()
        results: List[Dict] = []
        for row in rows:
            results.append(
                {
                    "timestamp": row["timestamp"],
                    "rule_name": row["rule_name"],
                    "severity": row["severity"],
                    "src_ip": row["src_ip"],
                    "user": row["user"],
                    "message": row["message"],
                }
            )
        return results


# TEST BLOCK
if __name__ == "__main__":
    from datetime import datetime

    storage = SQLiteStorage()
    storage.connect()
    storage.init_db()

    ev = Event(
        timestamp=datetime.utcnow().isoformat(),
        source="auth.log",
        raw="sample log line",
        action="login_failed",
        user="testuser",
        src_ip="10.0.0.1",
    )

    event_id = storage.insert_event(ev)
    print(f"Inserted event with id {event_id}")

    assert storage.conn is not None
    cur = storage.conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM events")
    row = cur.fetchone()
    print(f"Total events in DB: {row['c']}")

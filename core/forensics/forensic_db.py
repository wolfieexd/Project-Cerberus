import sqlite3
import os
from contextlib import contextmanager

class ForensicDatabase:
    """
    Manages the audit.db database for storing structured forensic logs.
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details_json TEXT NOT NULL,
        chain_hash TEXT NOT NULL
    );
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._initialize_db()
        
    def _initialize_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(self.SCHEMA)
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = FULL;")
            
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def insert_log(self, timestamp: str, event_type: str, details_json: str, chain_hash: str) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, event_type, details_json, chain_hash)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, event_type, details_json, chain_hash)
            )

    def get_last_log(self) -> dict:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            if row:
                return {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "details_json": row["details_json"],
                    "chain_hash": row["chain_hash"]
                }
        return None

    def get_all_logs(self) -> list:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
            return [dict(row) for row in rows]

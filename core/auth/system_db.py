import sqlite3
import os
import datetime
from contextlib import contextmanager

class SystemDatabase:
    """
    Manages the system.db database on the read-only partition (simulated).
    Tracks authentication attempts, timers, and trusted devices.
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS auth_attempts (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        max_attempts INTEGER NOT NULL DEFAULT 3,
        failed_count INTEGER NOT NULL DEFAULT 0,
        successful_count INTEGER NOT NULL DEFAULT 0,
        is_locked_out INTEGER NOT NULL DEFAULT 0,
        last_attempt_at TEXT
    );
    
    CREATE TABLE IF NOT EXISTS timer_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        initial_duration_ms INTEGER NOT NULL DEFAULT 120000,
        remaining_ms INTEGER NOT NULL DEFAULT 120000,
        last_tick_at TEXT,
        is_running INTEGER NOT NULL DEFAULT 0,
        is_expired INTEGER NOT NULL DEFAULT 0
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
            
            # Ensure singleton rows exist
            if not conn.execute("SELECT id FROM auth_attempts WHERE id = 1").fetchone():
                conn.execute("INSERT INTO auth_attempts (id) VALUES (1)")
            if not conn.execute("SELECT id FROM timer_state WHERE id = 1").fetchone():
                conn.execute("INSERT INTO timer_state (id) VALUES (1)")

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

    def get_failed_attempts(self) -> int:
        with self.get_connection() as conn:
            row = conn.execute("SELECT failed_count FROM auth_attempts WHERE id = 1").fetchone()
            return row['failed_count'] if row else 0

    def get_max_attempts(self) -> int:
        with self.get_connection() as conn:
            row = conn.execute("SELECT max_attempts FROM auth_attempts WHERE id = 1").fetchone()
            return row['max_attempts'] if row else 3

    def is_locked_out(self) -> bool:
        with self.get_connection() as conn:
            row = conn.execute("SELECT is_locked_out FROM auth_attempts WHERE id = 1").fetchone()
            return bool(row['is_locked_out'])

    def record_failed_attempt(self) -> bool:
        """
        Increments failed count. Returns True if lockout was triggered.
        """
        now = datetime.datetime.utcnow().isoformat()
        with self.get_connection() as conn:
            conn.execute("UPDATE auth_attempts SET failed_count = failed_count + 1, last_attempt_at = ? WHERE id = 1", (now,))
            
            # Check for lockout
            row = conn.execute("SELECT failed_count, max_attempts FROM auth_attempts WHERE id = 1").fetchone()
            if row['failed_count'] >= row['max_attempts']:
                conn.execute("UPDATE auth_attempts SET is_locked_out = 1 WHERE id = 1")
                return True
        return False

    def record_successful_attempt(self) -> None:
        """
        Resets failed count on success.
        """
        now = datetime.datetime.utcnow().isoformat()
        with self.get_connection() as conn:
            conn.execute("UPDATE auth_attempts SET successful_count = successful_count + 1, failed_count = 0, last_attempt_at = ? WHERE id = 1", (now,))

    def get_timer_state(self) -> dict:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM timer_state WHERE id = 1").fetchone()
            if row:
                return {
                    "initial_duration_ms": row["initial_duration_ms"],
                    "remaining_ms": row["remaining_ms"],
                    "last_tick_at": row["last_tick_at"],
                    "is_running": bool(row["is_running"]),
                    "is_expired": bool(row["is_expired"])
                }
        return {}

    def update_timer_state(self, remaining_ms: int, is_running: bool, is_expired: bool) -> None:
        now = datetime.datetime.utcnow().isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE timer_state 
                SET remaining_ms = ?, is_running = ?, is_expired = ?, last_tick_at = ? 
                WHERE id = 1
                """,
                (remaining_ms, int(is_running), int(is_expired), now)
            )



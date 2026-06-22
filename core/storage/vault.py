import sqlite3
import os
import uuid
import hashlib
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from contextlib import contextmanager

@dataclass
class EncryptedFileRecord:
    file_uuid: str
    original_name_ct: bytes
    original_size: int
    storage_path: str
    file_nonce: bytes
    created_at: str
    chunk_count: int

@dataclass
class ChunkRecord:
    file_uuid: str
    chunk_index: int
    chunk_nonce: bytes
    chunk_size: int
    storage_path: str
    chunk_hash: str

class VaultDatabase:
    """
    Manages the encrypted vault SQLite database (vault.db).
    Handles schema creation, file indexing, and metadata operations.
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS encrypted_file_index (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_uuid TEXT NOT NULL UNIQUE,
        original_name_ct BLOB NOT NULL,
        original_size INTEGER NOT NULL,
        storage_path TEXT NOT NULL,
        file_nonce BLOB NOT NULL,
        chunk_count INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        is_deleted INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS file_chunks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_uuid TEXT NOT NULL,
        chunk_index INTEGER NOT NULL,
        chunk_nonce BLOB NOT NULL,
        chunk_size INTEGER NOT NULL,
        storage_path TEXT NOT NULL,
        chunk_hash TEXT NOT NULL,
        FOREIGN KEY (file_uuid) REFERENCES encrypted_file_index(file_uuid),
        UNIQUE(file_uuid, chunk_index)
    );

    CREATE INDEX IF NOT EXISTS idx_file_uuid ON encrypted_file_index(file_uuid);
    CREATE INDEX IF NOT EXISTS idx_chunk_file ON file_chunks(file_uuid);
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._initialize_db()
        
    def _initialize_db(self):
        """Creates the database and schema if it does not exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(self.SCHEMA)
            
            # Apply performance/durability pragmas
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = FULL;")
            conn.execute("PRAGMA foreign_keys = ON;")

    @contextmanager
    def get_connection(self):
        """Context manager for SQLite connections."""
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

    def add_file_record(self, record: EncryptedFileRecord) -> None:
        """Adds a new file to the encrypted index."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO encrypted_file_index 
                (file_uuid, original_name_ct, original_size, storage_path, file_nonce, chunk_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.file_uuid,
                    record.original_name_ct,
                    record.original_size,
                    record.storage_path,
                    record.file_nonce,
                    record.chunk_count,
                    record.created_at
                )
            )

    def add_chunk_record(self, record: ChunkRecord) -> None:
        """Adds a chunk record associated with a file."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO file_chunks 
                (file_uuid, chunk_index, chunk_nonce, chunk_size, storage_path, chunk_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.file_uuid,
                    record.chunk_index,
                    record.chunk_nonce,
                    record.chunk_size,
                    record.storage_path,
                    record.chunk_hash
                )
            )

    def get_file_record(self, file_uuid: str) -> Optional[EncryptedFileRecord]:
        """Retrieves a file record by UUID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM encrypted_file_index WHERE file_uuid = ? AND is_deleted = 0", 
                (file_uuid,)
            ).fetchone()
            
            if row:
                return EncryptedFileRecord(
                    file_uuid=row['file_uuid'],
                    original_name_ct=row['original_name_ct'],
                    original_size=row['original_size'],
                    storage_path=row['storage_path'],
                    file_nonce=row['file_nonce'],
                    created_at=row['created_at'],
                    chunk_count=row['chunk_count']
                )
        return None

    def get_file_chunks(self, file_uuid: str) -> List[ChunkRecord]:
        """Retrieves all chunk records for a file, ordered by index."""
        chunks = []
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM file_chunks WHERE file_uuid = ? ORDER BY chunk_index ASC", 
                (file_uuid,)
            ).fetchall()
            
            for row in rows:
                chunks.append(ChunkRecord(
                    file_uuid=row['file_uuid'],
                    chunk_index=row['chunk_index'],
                    chunk_nonce=row['chunk_nonce'],
                    chunk_size=row['chunk_size'],
                    storage_path=row['storage_path'],
                    chunk_hash=row['chunk_hash']
                ))
        return chunks

    def list_files(self) -> List[EncryptedFileRecord]:
        """Lists all non-deleted files in the vault."""
        files = []
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM encrypted_file_index WHERE is_deleted = 0").fetchall()
            for row in rows:
                files.append(EncryptedFileRecord(
                    file_uuid=row['file_uuid'],
                    original_name_ct=row['original_name_ct'],
                    original_size=row['original_size'],
                    storage_path=row['storage_path'],
                    file_nonce=row['file_nonce'],
                    created_at=row['created_at'],
                    chunk_count=row['chunk_count']
                ))
        return files

    def mark_deleted(self, file_uuid: str) -> None:
        """Soft deletes a file from the index."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE encrypted_file_index SET is_deleted = 1 WHERE file_uuid = ?", 
                (file_uuid,)
            )

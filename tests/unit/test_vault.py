import pytest
import os
import uuid
import datetime

from core.storage.vault import VaultDatabase, EncryptedFileRecord, ChunkRecord

@pytest.fixture
def temp_db(tmp_path):
    db_path = str(tmp_path / "vault.db")
    db = VaultDatabase(db_path)
    yield db
    # Cleanup if needed

def test_vault_initialization(temp_db):
    assert os.path.exists(temp_db.db_path)

def test_add_and_get_file_record(temp_db):
    file_uuid = str(uuid.uuid4())
    record = EncryptedFileRecord(
        file_uuid=file_uuid,
        original_name_ct=b"encrypted_name",
        original_size=1024,
        storage_path="/path/to/data",
        file_nonce=b"123456789012",
        created_at=datetime.datetime.utcnow().isoformat(),
        chunk_count=2
    )
    
    temp_db.add_file_record(record)
    
    fetched = temp_db.get_file_record(file_uuid)
    assert fetched is not None
    assert fetched.file_uuid == file_uuid
    assert fetched.original_name_ct == b"encrypted_name"
    assert fetched.chunk_count == 2

def test_add_and_get_chunks(temp_db):
    file_uuid = str(uuid.uuid4())
    
    # Add dummy file record first (foreign key constraint)
    temp_db.add_file_record(EncryptedFileRecord(
        file_uuid=file_uuid,
        original_name_ct=b"ct",
        original_size=10,
        storage_path="",
        file_nonce=b"123",
        created_at="",
        chunk_count=2
    ))
    
    chunk1 = ChunkRecord(
        file_uuid=file_uuid,
        chunk_index=0,
        chunk_nonce=b"nonce1",
        chunk_size=1024,
        storage_path="/path/c0",
        chunk_hash="hash0"
    )
    chunk2 = ChunkRecord(
        file_uuid=file_uuid,
        chunk_index=1,
        chunk_nonce=b"nonce2",
        chunk_size=512,
        storage_path="/path/c1",
        chunk_hash="hash1"
    )
    
    temp_db.add_chunk_record(chunk1)
    temp_db.add_chunk_record(chunk2)
    
    chunks = temp_db.get_file_chunks(file_uuid)
    assert len(chunks) == 2
    assert chunks[0].chunk_index == 0
    assert chunks[1].chunk_index == 1

def test_soft_delete(temp_db):
    file_uuid = str(uuid.uuid4())
    record = EncryptedFileRecord(
        file_uuid=file_uuid,
        original_name_ct=b"encrypted_name",
        original_size=1024,
        storage_path="/path/to/data",
        file_nonce=b"123456789012",
        created_at=datetime.datetime.utcnow().isoformat(),
        chunk_count=1
    )
    temp_db.add_file_record(record)
    
    assert temp_db.get_file_record(file_uuid) is not None
    
    temp_db.mark_deleted(file_uuid)
    assert temp_db.get_file_record(file_uuid) is None
    
    files = temp_db.list_files()
    assert len(files) == 0

import pytest
import os
import shutil

from core.crypto.aes_engine import AESEngine
from core.storage.storage_manager import StorageManager

@pytest.fixture
def storage_env(tmp_path):
    db_path = str(tmp_path / "vault.db")
    data_dir = str(tmp_path / "data")
    
    # 256-bit test key
    key = bytes([0] * 32)
    aes_engine = AESEngine(key)
    
    manager = StorageManager(db_path, data_dir, aes_engine)
    
    yield manager, tmp_path

def test_add_and_extract_file(storage_env):
    manager, tmp_path = storage_env
    
    # Create a test file
    test_file_path = str(tmp_path / "secret.txt")
    with open(test_file_path, "wb") as f:
        f.write(b"Hello, Secure World!" * 1000) # Ensure it has some size
        
    # Add file to storage
    file_uuid = manager.add_file(test_file_path)
    assert file_uuid is not None
    
    # Verify it exists in listing
    files = manager.list_files()
    assert len(files) == 1
    assert files[0]['file_uuid'] == file_uuid
    assert files[0]['original_name'] == "secret.txt"
    
    # Extract file
    extract_dir = str(tmp_path / "extracted")
    os.makedirs(extract_dir)
    extracted_path = manager.extract_file(file_uuid, extract_dir)
    
    # Verify contents
    assert os.path.exists(extracted_path)
    with open(extracted_path, "rb") as f:
        content = f.read()
        assert content == b"Hello, Secure World!" * 1000

def test_chunking_large_file(storage_env):
    manager, tmp_path = storage_env
    
    # Lower chunk size for test
    manager.chunk_manager.chunk_size = 1024 # 1 KB chunks
    
    test_file_path = str(tmp_path / "large.bin")
    with open(test_file_path, "wb") as f:
        f.write(os.urandom(2500)) # Will create 3 chunks (1024, 1024, 452)
        
    file_uuid = manager.add_file(test_file_path)
    
    files = manager.list_files()
    assert files[0]['chunk_count'] == 3
    
    extract_dir = str(tmp_path / "extracted")
    extracted_path = manager.extract_file(file_uuid, extract_dir)
    
    assert os.path.getsize(extracted_path) == 2500

def test_delete_file(storage_env):
    manager, tmp_path = storage_env
    
    test_file_path = str(tmp_path / "delete_me.txt")
    with open(test_file_path, "wb") as f:
        f.write(b"Temp")
        
    file_uuid = manager.add_file(test_file_path)
    
    assert len(manager.list_files()) == 1
    manager.delete_file(file_uuid)
    assert len(manager.list_files()) == 0

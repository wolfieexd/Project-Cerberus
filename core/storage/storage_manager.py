import os
import uuid
import datetime
from typing import List

from core.crypto.aes_engine import AESEngine, NonceManager
from core.storage.vault import VaultDatabase, EncryptedFileRecord, ChunkRecord
from core.storage.chunk_manager import ChunkManager

class StorageManager:
    """
    High-level interface for the secure storage layer.
    Orchestrates file chunking, encryption, and vault indexing.
    """
    
    def __init__(self, db_path: str, data_dir: str, aes_engine: AESEngine):
        self.vault_db = VaultDatabase(db_path)
        self.chunk_manager = ChunkManager(aes_engine)
        self.aes_engine = aes_engine
        self.data_dir = data_dir
        self.nonce_manager = NonceManager()
        
        os.makedirs(self.data_dir, exist_ok=True)
        
    def add_file(self, file_path: str) -> str:
        """
        Encrypts a file and adds it to the vault.
        Returns the unique file_uuid.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        file_uuid = str(uuid.uuid4())
        original_name = os.path.basename(file_path).encode('utf-8')
        original_size = os.path.getsize(file_path)
        
        # Encrypt the original filename for privacy
        name_nonce, name_ct = self.aes_engine.encrypt(original_name)
        
        # We'll store chunks in a subdirectory based on the file UUID
        file_data_dir = os.path.join(self.data_dir, file_uuid)
        
        chunk_count = 0
        # Stream encrypt the file in chunks and add records
        for chunk_idx, chunk_nonce, chunk_size, chunk_path, chunk_hash in self.chunk_manager.encrypt_file(
            file_path, file_data_dir, file_uuid
        ):
            chunk_record = ChunkRecord(
                file_uuid=file_uuid,
                chunk_index=chunk_idx,
                chunk_nonce=chunk_nonce,
                chunk_size=chunk_size,
                storage_path=chunk_path,
                chunk_hash=chunk_hash
            )
            self.vault_db.add_chunk_record(chunk_record)
            chunk_count += 1
            
        # Add file record to index
        now_iso = datetime.datetime.utcnow().isoformat()
        
        file_record = EncryptedFileRecord(
            file_uuid=file_uuid,
            original_name_ct=name_ct,
            original_size=original_size,
            storage_path=file_data_dir,
            file_nonce=name_nonce,
            created_at=now_iso,
            chunk_count=chunk_count
        )
        self.vault_db.add_file_record(file_record)
        
        return file_uuid
        
    def extract_file(self, file_uuid: str, dest_dir: str) -> str:
        """
        Decrypts a file from the vault to the specified destination directory.
        Returns the path to the extracted plaintext file.
        """
        file_record = self.vault_db.get_file_record(file_uuid)
        if not file_record:
            raise ValueError(f"File {file_uuid} not found in vault")
            
        chunks = self.vault_db.get_file_chunks(file_uuid)
        if not chunks:
            raise ValueError(f"No chunks found for file {file_uuid}")
            
        # Decrypt original filename
        original_name_bytes = self.aes_engine.decrypt(file_record.file_nonce, file_record.original_name_ct)
        original_name = original_name_bytes.decode('utf-8')
        
        dest_path = os.path.join(dest_dir, original_name)
        
        # Reconstruct and decrypt file
        self.chunk_manager.decrypt_file(chunks, dest_path)
        
        return dest_path
        
    def list_files(self) -> List[dict]:
        """
        Lists all files in the vault, returning their decrypted names and metadata.
        """
        records = self.vault_db.list_files()
        result = []
        
        for record in records:
            try:
                name_bytes = self.aes_engine.decrypt(record.file_nonce, record.original_name_ct)
                name = name_bytes.decode('utf-8')
            except Exception:
                name = "<Decryption Failed>"
                
            result.append({
                "file_uuid": record.file_uuid,
                "original_name": name,
                "original_size": record.original_size,
                "created_at": record.created_at,
                "chunk_count": record.chunk_count
            })
            
        return result
        
    def delete_file(self, file_uuid: str) -> None:
        """
        Soft deletes the file from the index.
        """
        self.vault_db.mark_deleted(file_uuid)
        # Note: Actual file deletion or chunk shredding would depend on the 
        # crypto-shredding requirements. For soft-delete, we just mark it.

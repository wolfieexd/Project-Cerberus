import os
from cryptography.exceptions import InvalidTag

from core.auth.system_db import SystemDatabase
from core.storage.vault import VaultDatabase
from core.storage.storage_manager import StorageManager
from core.crypto.key_manager import KeyManager, WrappedKeyBlob
from core.crypto.aes_engine import AESEngine

class AuthManager:
    """
    Manages user authentication, attempt limits, and vault access.
    """
    
    def __init__(self, system_db_path: str, vault_db_path: str, data_dir: str, key_manager: KeyManager):
        self.system_db = SystemDatabase(system_db_path)
        self.vault_db = VaultDatabase(vault_db_path)
        self.data_dir = data_dir
        self.key_manager = key_manager
        
    def setup_new_vault(self, password: str) -> None:
        """
        Initializes a new vault with a given password.
        """
        # Generate and wrap new MEK
        mek = self.key_manager.generate_mek()
        blob = self.key_manager.wrap_mek(password, mek)
        
        # Store in vault
        self.vault_db.store_key_blob(blob.salt, blob.wrapped_key_with_tag, blob.nonce)

    def authenticate(self, password: str) -> StorageManager:
        """
        Attempts to authenticate with the given password.
        Returns a configured StorageManager if successful.
        Raises PermissionError if locked out or InvalidTag on wrong password.
        """
        if self.system_db.is_locked_out():
            raise PermissionError("System is locked due to too many failed attempts.")
            
        key_data = self.vault_db.get_key_blob()
        if not key_data:
            raise ValueError("Vault is not initialized.")
            
        blob = WrappedKeyBlob(
            salt=key_data["salt"],
            nonce=key_data["nonce"],
            wrapped_key_with_tag=key_data["wrapped_mek"]
        )
        
        try:
            # Try to unwrap MEK
            mek = self.key_manager.unwrap_mek(password, blob)
            
            # If successful, reset failed attempts
            self.system_db.record_successful_attempt()
            
            # Initialize AESEngine with the unwrapped MEK
            aes_engine = AESEngine(mek)
            
            return StorageManager(self.vault_db.db_path, self.data_dir, aes_engine)
            
        except InvalidTag:
            # Wrong password
            locked_out = self.system_db.record_failed_attempt()
            if locked_out:
                # Trigger crypto-shredding (to be implemented)
                pass
            raise
            
    def get_remaining_attempts(self) -> int:
        max_att = self.system_db.get_max_attempts()
        failed = self.system_db.get_failed_attempts()
        return max(0, max_att - failed)

    def is_locked_out(self) -> bool:
        return self.system_db.is_locked_out()

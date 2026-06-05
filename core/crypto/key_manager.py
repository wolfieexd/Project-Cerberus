import os
from dataclasses import dataclass

from core.crypto.aes_engine import AESEngine
from core.crypto.kdf import KDFEngine
from core.crypto.secure_memory import SecureMemory, wipe_bytes_if_possible

@dataclass
class WrappedKeyBlob:
    """
    Data class representing a wrapped key and its necessary metadata.
    """
    salt: bytes
    nonce: bytes
    wrapped_key_with_tag: bytes

class KeyManager:
    """
    Manages the lifecycle of the Key Encryption Key (KEK) and 
    Media Encryption Key (MEK).
    """
    
    def __init__(self, kdf_engine: KDFEngine = None):
        self.kdf_engine = kdf_engine or KDFEngine()
        self.secure_memory = SecureMemory()
        
    def generate_mek(self) -> bytes:
        """
        Generates a 32-byte (256-bit) Media Encryption Key (MEK).
        """
        return os.urandom(32)
        
    def derive_kek(self, password: str, salt: bytes) -> bytes:
        """
        Derives the Key Encryption Key (KEK) from the user's password.
        """
        return self.kdf_engine.derive_key(password, salt)
        
    def wrap_mek(self, password: str, mek: bytes) -> WrappedKeyBlob:
        """
        Derives a KEK from the password and uses it to wrap (encrypt) the MEK.
        Returns a WrappedKeyBlob containing the salt, nonce, and ciphertext.
        """
        salt = self.kdf_engine.generate_salt()
        kek = self.derive_kek(password, salt)
        
        try:
            aes_engine = AESEngine(kek)
            nonce, wrapped_mek = aes_engine.encrypt(mek)
            return WrappedKeyBlob(salt=salt, nonce=nonce, wrapped_key_with_tag=wrapped_mek)
        finally:
            # Wipe KEK from memory after use
            wipe_bytes_if_possible(kek)
            
    def unwrap_mek(self, password: str, blob: WrappedKeyBlob) -> bytes:
        """
        Derives the KEK from the password and uses it to unwrap (decrypt) the MEK.
        Raises InvalidTag if the password is wrong or the blob is tampered.
        """
        kek = self.derive_kek(password, blob.salt)
        
        try:
            aes_engine = AESEngine(kek)
            mek = aes_engine.decrypt(blob.nonce, blob.wrapped_key_with_tag)
            return mek
        finally:
            # Wipe KEK from memory after use
            wipe_bytes_if_possible(kek)

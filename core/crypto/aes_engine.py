import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class NonceManager:
    """
    Generates and tracks nonces to ensure uniqueness.
    GCM requires absolutely unique nonces for each key.
    """
    
    def __init__(self, nonce_length: int = 12):
        self.nonce_length = nonce_length
    
    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random nonce.
        For AES-GCM, the recommended size is 12 bytes (96 bits).
        """
        return os.urandom(self.nonce_length)

class AESEngine:
    """
    Handles AES-256-GCM authenticated encryption and decryption.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize the AES engine with a 32-byte (256-bit) key.
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
            
        self._key = key
        self._aesgcm = AESGCM(self._key)
        self._nonce_manager = NonceManager()
        
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-GCM.
        Returns (nonce, ciphertext_with_tag).
        The authentication tag is appended to the ciphertext automatically.
        """
        nonce = self._nonce_manager.generate_nonce()
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
        
    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypts ciphertext and validates the authentication tag.
        Raises InvalidTag if decryption fails.
        """
        return self._aesgcm.decrypt(nonce, ciphertext, associated_data)

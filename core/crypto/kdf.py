import os
from argon2 import low_level

class KDFEngine:
    """
    Key Derivation Function Engine using Argon2id.
    Derives cryptographic keys from passwords.
    """
    
    def __init__(
        self,
        time_cost: int = 4,
        memory_cost: int = 262144,  # 256 MiB
        parallelism: int = 8,
        hash_len: int = 32,         # 256-bit output for AES-256
        salt_len: int = 16
    ):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len

    def generate_salt(self) -> bytes:
        """
        Generate a random salt for KDF.
        """
        return os.urandom(self.salt_len)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a raw byte key from a password and salt using Argon2id.
        """
        if not password:
            raise ValueError("Password cannot be empty")
            
        if len(salt) != self.salt_len:
            raise ValueError(f"Salt must be {self.salt_len} bytes")
            
        raw_key = low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            type=low_level.Type.ID
        )
        
        return raw_key

import os
import hashlib
from typing import Iterator, Tuple

from core.crypto.aes_engine import AESEngine, NonceManager

class ChunkManager:
    """
    Handles streaming encryption and decryption of large files in chunks
    to avoid memory exhaustion.
    """
    
    DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
    
    def __init__(self, aes_engine: AESEngine, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.aes_engine = aes_engine
        self.chunk_size = chunk_size
        self.nonce_manager = NonceManager()
        
    def read_in_chunks(self, file_path: str) -> Iterator[bytes]:
        """Generator that reads a file in chunks."""
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(self.chunk_size)
                if not data:
                    break
                yield data

    def encrypt_file(self, input_path: str, output_dir: str, file_uuid: str) -> Iterator[Tuple[int, bytes, int, str, str]]:
        """
        Encrypts a file in chunks.
        Yields (chunk_index, chunk_nonce, chunk_size, output_path, chunk_hash)
        for each chunk processed.
        """
        os.makedirs(output_dir, exist_ok=True)
        
        chunk_index = 0
        for chunk_data in self.read_in_chunks(input_path):
            # Encrypt the chunk
            nonce, ciphertext = self.aes_engine.encrypt(chunk_data)
            
            # Generate output path
            chunk_filename = f"{file_uuid}_{chunk_index:04d}.enc"
            chunk_path = os.path.join(output_dir, chunk_filename)
            
            # Write encrypted chunk to disk
            with open(chunk_path, 'wb') as f:
                f.write(ciphertext)
                
            # Calculate hash of ciphertext for integrity
            chunk_hash = hashlib.sha256(ciphertext).hexdigest()
            
            yield (chunk_index, nonce, len(chunk_data), chunk_path, chunk_hash)
            chunk_index += 1

    def decrypt_chunk(self, chunk_path: str, nonce: bytes) -> bytes:
        """
        Reads and decrypts a single chunk from disk.
        """
        with open(chunk_path, 'rb') as f:
            ciphertext = f.read()
            
        return self.aes_engine.decrypt(nonce, ciphertext)

    def decrypt_file(self, chunks: list, output_path: str) -> None:
        """
        Decrypts a list of chunks (ordered) and reconstructs the original file.
        `chunks` should be a list of ChunkRecord objects or dicts with 
        'storage_path' and 'chunk_nonce'.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        with open(output_path, 'wb') as f_out:
            for chunk in chunks:
                plaintext = self.decrypt_chunk(chunk.storage_path, chunk.chunk_nonce)
                f_out.write(plaintext)

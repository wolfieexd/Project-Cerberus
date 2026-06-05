import ctypes
import os
import platform

class SecureMemory:
    """
    Provides secure memory utilities to protect cryptographic key material.
    On Windows, uses VirtualLock to prevent paging to disk and 
    SecureZeroMemory to securely wipe memory.
    """
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        
        if self.is_windows:
            self.kernel32 = ctypes.windll.kernel32
    
    def create_secure_buffer(self, size: int) -> ctypes.Array:
        """
        Creates a mutable ctypes character buffer that can be zeroized.
        """
        return ctypes.create_string_buffer(size)
    
    def lock_memory(self, buffer: ctypes.Array) -> bool:
        """
        Locks the buffer in RAM to prevent it from being paged to the swap file.
        """
        if not self.is_windows:
            return False
            
        size = ctypes.sizeof(buffer)
        result = self.kernel32.VirtualLock(ctypes.byref(buffer), ctypes.c_size_t(size))
        return bool(result)
        
    def unlock_memory(self, buffer: ctypes.Array) -> bool:
        """
        Unlocks the previously locked buffer.
        """
        if not self.is_windows:
            return False
            
        size = ctypes.sizeof(buffer)
        result = self.kernel32.VirtualUnlock(ctypes.byref(buffer), ctypes.c_size_t(size))
        return bool(result)
        
    def zeroize(self, buffer: ctypes.Array) -> None:
        """
        Securely overwrites the buffer with zeros.
        """
        size = ctypes.sizeof(buffer)
        
        if self.is_windows:
            self.kernel32.SecureZeroMemory(ctypes.byref(buffer), ctypes.c_size_t(size))
        else:
            # Fallback for non-Windows platforms during development/testing
            ctypes.memset(ctypes.byref(buffer), 0, size)

def wipe_bytes_if_possible(b: bytes) -> None:
    """
    Attempt to wipe immutable bytes object. In Python this is not guaranteed 
    as bytes are immutable, but we can try to overwrite the underlying buffer.
    WARNING: Use ctypes buffers for sensitive data instead of Python bytes.
    """
    if not isinstance(b, bytes):
        return
        
    try:
        # Very hacky way to modify immutable bytes. Best effort only.
        import ctypes
        buf = (ctypes.c_char * len(b)).from_address(id(b) + 32)
        ctypes.memset(buf, 0, len(b))
    except Exception:
        pass

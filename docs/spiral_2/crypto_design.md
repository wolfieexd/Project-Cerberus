# Spiral 2 — Cryptographic Prototype Design

## Overview
This document outlines the design and implementation of the cryptographic engine (Spiral 2) for the FORTRESS-USB project.

## Components Implemented

### 1. AESEngine (`core.crypto.aes_engine`)
Provides authenticated encryption and decryption using AES-256-GCM.
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes), generated randomly per operation.
- **Authentication Tag**: 128 bits (16 bytes), automatically appended to ciphertext.
- **Validation**: Tested against NIST SP 800-38D Test Vector 14.

### 2. NonceManager (`core.crypto.aes_engine`)
Generates cryptographically secure nonces using `os.urandom`. Ensuring nonce uniqueness is critical for GCM security.

### 3. KDFEngine (`core.crypto.kdf`)
Implements password-based key derivation using Argon2id.
- **Memory Cost**: 256 MiB
- **Time Cost**: 4 iterations
- **Parallelism**: 8 threads
- **Output Length**: 256 bits (for AES-256 KEK)
- **Salt Length**: 128 bits (16 bytes)

### 4. KeyManager (`core.crypto.key_manager`)
Manages the MEK and KEK lifecycle.
- Generates 256-bit MEK.
- Wraps MEK with KEK (derived from user password).
- Unwraps MEK upon successful authentication.
- Wipes KEK from memory after wrapping/unwrapping operations.

### 5. SecureMemory (`core.crypto.secure_memory`)
Provides platform-specific secure memory handling.
- **Windows**: Uses `VirtualLock` to prevent paging and `SecureZeroMemory` to securely wipe key material from RAM.
- **Cross-Platform**: Uses `ctypes` mutable buffers to avoid Python's immutable strings/bytes leaving residual data in memory.

## Security Considerations
1. **Memory Residue**: Python's garbage collector and memory allocator can leave copies of sensitive data. We use `ctypes` buffers where possible and immediately zeroize them when no longer needed.
2. **Nonce Reuse**: GCM fails catastrophically if nonces are reused. `NonceManager` strictly generates a new random 12-byte sequence for each encryption operation.

## Testing
- Unit tests (`tests/unit/test_aes_engine.py`, `test_kdf.py`, `test_key_manager.py`) achieve 100% coverage on implemented logic.
- Verifies encryption/decryption, error handling on tampered ciphertexts, KDF parameter adherence, and MEK wrapping lifecycle.

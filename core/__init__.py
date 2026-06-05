"""
FORTRESS-USB: Advanced Self-Protecting Encrypted Removable Storage System

A production-quality secure removable USB storage system implementing:
- AES-256-GCM encryption with MEK/KEK architecture
- Argon2id key derivation
- Crypto-shredding for irreversible data destruction
- Persistent countdown timer (survives USB removal)
- Authentication attempt limiting with persistence
- Trusted host validation (TPM + machine fingerprinting)
- Forensic evidence collection before destruction
- Professional PySide6 GUI

Hardware Target: Phison PS2251-67 (software-controlled security)
"""

__version__ = "1.0.0"
__project__ = "FORTRESS-USB"
__author__ = "FORTRESS Security Engineering Team"

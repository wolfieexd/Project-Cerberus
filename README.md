# Advanced Self-Protecting Encrypted Removable Storage System

## Project Codename: **Cerberus**

[![Security](https://img.shields.io/badge/Security-AES--256--GCM-green)]()
[![KDF](https://img.shields.io/badge/KDF-Argon2id-blue)]()
[![Controller](https://img.shields.io/badge/Controller-Phison%20PS2251--67-orange)]()
[![License](https://img.shields.io/badge/License-Proprietary-red)]()

---

## Overview

Project Cerberus is a production-quality secure removable storage system that protects 
sensitive information through a multi-layered cryptographic architecture. The system 
provides defense-in-depth against unauthorized access, USB theft, brute-force attacks, 
and offline extraction attempts.

## Key Security Features

| Feature | Description |
|---|---|
| **AES-256-GCM Encryption** | Full-disk encryption with authenticated encryption |
| **MEK/KEK Architecture** | Layered key management with media encryption keys |
| **Crypto-Shredding** | Irreversible key destruction rendering data irrecoverable |
| **Trusted Host Validation** | TPM/hardware fingerprint-based automatic unlock |
| **Persistent Timer** | Survives power loss, USB removal, and reboots |
| **Attempt Limiting** | Maximum 3 authentication attempts with persistence |
| **Forensic Logging** | Pre-destruction evidence collection |
| **Self-Destruction** | Automatic key destruction on security violations |

## Development Methodology

This project follows a **Risk-Driven Spiral SDLC** with 12 iterative phases:

| Spiral | Phase | Status |
|--------|-------|--------|
| 1 | Requirements, Threat Modeling, Architecture | ✅ Complete |
| 2 | Cryptographic Prototype | ✅ Complete |
| 3 | Secure Storage Layer | ✅ Complete |
| 4 | Authentication Layer | ✅ Complete |
| 5 | Persistent Timer Layer | ✅ Complete |
| 6 | Trusted Device Framework | 🚫 Skipped (Zero Trust Policy) |
| 7 | Forensic Logging Engine | ⏳ Pending |
| 8 | Crypto-Shredding Engine | ⏳ Pending |
| 9 | GUI Application | ⏳ Pending |
| 10 | System Integration | ⏳ Pending |
| 11 | Penetration Testing | ⏳ Pending |
| 12 | Documentation & Deployment | ⏳ Pending |

## Hardware Target

- **Controller**: Phison PS2251-67
- **Storage**: 16GB USB Flash Drive
- **Architecture**: Software-controlled security with firmware migration path

## Technology Stack

- **Backend**: Python 3.11+
- **GUI**: PySide6
- **Cryptography**: `cryptography`, `argon2-cffi`
- **Database**: SQLite (encrypted)
- **Logging**: Structured JSON
- **Packaging**: PyInstaller

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python -m secure_usb.main
```

## Project Structure

```
secure_usb/
├── core/              # Core system logic
│   ├── crypto/        # Cryptographic engine (AES-256-GCM, Argon2id)
│   ├── storage/       # Encrypted storage layer
│   ├── auth/          # Authentication & access control
│   ├── timer/         # Persistent countdown timer
│   ├── forensics/     # Forensic logging engine
│   └── shredding/     # Crypto-shredding engine
├── gui/               # PySide6 GUI application
├── trusted/           # Trusted device framework
├── tests/             # Test suite
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   └── security/      # Security/penetration tests
├── docs/              # Documentation
│   ├── spiral_1/      # Spiral 1: Requirements & Architecture
│   ├── spiral_2/      # Spiral 2: Crypto Prototype
│   └── ...
├── config/            # Configuration files
└── scripts/           # Build & deployment scripts
```

## Security Notice

⚠️ **WARNING**: This system implements irreversible crypto-shredding. Once triggered, 
encrypted data becomes permanently irrecoverable. Use with extreme caution.


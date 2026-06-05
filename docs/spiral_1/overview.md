# Spiral 1 — Overview & Phase Report

## Phase: Requirements Analysis, Threat Modeling, Architecture Design

**Status**: ✅ Complete  
**Start Date**: 2026-06-02  
**Project**: FORTRESS-USB — Advanced Self-Protecting Encrypted Removable Storage System

---

## 1. Goal

Establish the complete requirements baseline, threat landscape, and system architecture
for a software-controlled secure USB storage system targeting the Phison PS2251-67 
controller with 16GB flash storage.

### Objectives

| # | Objective | Status |
|---|-----------|--------|
| 1 | Complete functional requirements analysis (40+ requirements) | ✅ |
| 2 | Complete non-functional requirements analysis (20+ NFRs) | ✅ |
| 3 | STRIDE-based threat model (40+ threats identified) | ✅ |
| 4 | System architecture with 10+ diagrams | ✅ |
| 5 | Database schema for all persistent state | ✅ |
| 6 | Architectural Decision Records (10 ADRs) | ✅ |
| 7 | Comprehensive testing strategy | ✅ |
| 8 | Hardware constraints analysis (Phison PS2251-67) | ✅ |
| 9 | Project directory structure and configuration | ✅ |
| 10 | Spiral 2 planning | ✅ |

---

## 2. Architecture Summary

### System Concept

```
┌──────────────────────────────────────────────────────────┐
│                     USB DRIVE (16 GB)                     │
│                                                          │
│  ┌─────────────────────┐  ┌────────────────────────────┐ │
│  │  PARTITION A (~100M) │  │   PARTITION B (~15.9 GB)    │ │
│  │  Read-Only Launcher  │  │   Encrypted Vault           │ │
│  │                     │  │                             │ │
│  │  • unlock.exe       │  │  • vault.db (keys, index)   │ │
│  │  • system.db        │  │  • Encrypted file blobs     │ │
│  │    - Timer state    │  │  • Forensic evidence        │ │
│  │    - Attempt counter│  │  • Chunk storage            │ │
│  │    - Trusted devices│  │                             │ │
│  │    - Audit log      │  │                             │ │
│  │  • config.json      │  │                             │ │
│  └─────────────────────┘  └────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
                          │
                          │ USB 2.0
                          ▼
┌──────────────────────────────────────────────────────────┐
│                    HOST MACHINE                           │
│                                                          │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────┐│
│  │  PySide6  │  │  Crypto   │  │  Timer   │  │Forensics││
│  │   GUI     │  │  Engine   │  │  Engine  │  │ Engine  ││
│  │          │  │           │  │          │  │         ││
│  │ Splash   │  │ AES-GCM   │  │ Persist  │  │ Collect ││
│  │ Unlock   │  │ Argon2id  │  │ Countdown│  │ Log     ││
│  │ Countdown│  │ MEK/KEK   │  │ Anti-    │  │ Chain   ││
│  │ Destroy  │  │ Wrapping  │  │ Tamper   │  │ HMAC    ││
│  └──────────┘  └───────────┘  └──────────┘  └─────────┘│
│                                                          │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────────┐  │
│  │  Auth    │  │  Trusted  │  │    Shredding         │  │
│  │  Manager │  │  Device   │  │    Engine             │  │
│  │          │  │  Manager  │  │                      │  │
│  │ Password │  │ TPM       │  │ MEK Destroy          │  │
│  │ Attempts │  │ UUID      │  │ KEK Destroy          │  │
│  │ Lockout  │  │ Fingerpt  │  │ Verify               │  │
│  └──────────┘  └───────────┘  └──────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Key Architecture Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| AD-001 | Software-only security | PS2251-67 has no hardware crypto; firmware mod impractical |
| AD-002 | AES-256-GCM (not XTS) | File-level encryption needs authenticated encryption |
| AD-003 | Argon2id 256 MiB | Maximum brute-force resistance for single-use unlock |
| AD-004 | Two-database architecture | Security state must survive crypto-shredding |
| AD-005 | HMAC anti-tamper | Detect state file modifications (timer, counter) |
| AD-006 | Crypto-shredding | Flash wear leveling makes physical deletion unreliable |
| AD-007 | DB-persisted timer | Survives USB removal, power loss, and reboots |
| AD-008 | Composite fingerprint | SHA-256(UUID + serial + SID) for stable host identity |
| AD-009 | PyInstaller single-file | No Python required on host; portable .exe from USB |
| AD-010 | Forensic evidence survives | Separate HMAC key; evidence readable after shred |

### Cryptographic Architecture

```
User Password ──────────────────────┐
                                    │
                                    ▼
                          ┌─────────────────┐
                          │    Argon2id      │
                          │  m=256MiB t=4    │
                          │  p=8 len=32      │
                          │  + 16-byte Salt  │
                          └────────┬────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │  KEK (256-bit)   │  ← Never stored; derived on-the-fly
                          └────────┬────────┘
                                   │
                          AES-256-GCM Unwrap
                                   │
                                   ▼
                          ┌─────────────────┐
                          │  MEK (256-bit)   │  ← Stored encrypted by KEK
                          └────────┬────────┘
                                   │
                          AES-256-GCM Encrypt/Decrypt
                                   │
                                   ▼
                          ┌─────────────────┐
                          │  User Data       │  ← Encrypted file blobs
                          └─────────────────┘
```

---

## 3. Risks Identified

### Top 10 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| 1 | **Key material in host RAM** | High | Critical | Minimize exposure; VirtualLock; SecureZeroMemory |
| 2 | **BadUSB firmware replacement** | Medium | Critical | Out of scope (hardware limitation); educate users |
| 3 | **Timer state tampering** | Medium | High | HMAC protection; device-bound key derivation |
| 4 | **Attempt counter reset** | Medium | High | HMAC protection; hash chain audit log |
| 5 | **Nonce reuse (GCM)** | Low | Critical | Random 12-byte nonces; database tracking |
| 6 | **NAND wear level key remnants** | Medium | Medium | Crypto-shredding (don't rely on overwrite) |
| 7 | **Host clock manipulation** | Medium | Medium | Monotonic clock + wall clock cross-reference |
| 8 | **Physical USB cloning** | Low | High | Timer/counter bound to original device |
| 9 | **Process memory dump** | Medium | High | Minimize key lifetime; privilege checks |
| 10 | **DLL injection/hooking** | Medium | High | Code signing; integrity checks; anti-debug |

### Risk Heatmap

```
Impact ↑
       │
  5    │  [R5]                      [R1][R2]
       │
  4    │                    [R8]    [R3][R4][R10]
       │
  3    │                    [R6]    [R9]
       │
  2    │                    [R7]
       │
  1    │
       └────────────────────────────────────────→
         1        2        3        4        5
                         Likelihood
```

---

## 4. Mitigations Summary

| Risk Category | Mitigation Approach |
|---------------|---------------------|
| **Memory exposure** | ctypes buffers, VirtualLock, SecureZeroMemory, minimal lifetime |
| **State tampering** | HMAC-SHA256 on all mutable state with device-bound keys |
| **Brute force** | Argon2id 256 MiB; max 3 attempts; persistent counter |
| **Offline attacks** | AES-256-GCM with 256-bit keys; authenticated encryption |
| **Timer bypass** | No reset code path; monotonic clock; HMAC-protected state |
| **Physical cloning** | Timer state HMAC bound to original device identity |
| **Firmware attacks** | Documented as known limitation; user education |
| **Key extraction** | Crypto-shredding instead of data deletion |

---

## 5. Folder Structure (Complete)

```
d:\Project Storage\secure_usb\
├── README.md                           # Project overview
├── requirements.txt                    # Production dependencies
├── requirements-dev.txt                # Development dependencies
├── config/
│   └── default_config.json             # Default configuration
├── core/
│   ├── __init__.py                     # Package: project metadata
│   ├── crypto/
│   │   └── __init__.py                 # Spiral 2: AES-GCM, Argon2id, key management
│   ├── storage/
│   │   └── __init__.py                 # Spiral 3: Encrypted storage layer
│   ├── auth/
│   │   └── __init__.py                 # Spiral 4: Authentication manager
│   ├── timer/
│   │   └── __init__.py                 # Spiral 6: Persistent timer
│   ├── forensics/
│   │   └── __init__.py                 # Spiral 7: Forensic logging engine
│   └── shredding/
│       └── __init__.py                 # Spiral 8: Crypto-shredding engine
├── gui/
│   └── __init__.py                     # Spiral 9: PySide6 GUI
├── trusted/
│   └── __init__.py                     # Spiral 5: Trusted device framework
├── launcher/                           # Spiral 12: PyInstaller packaging
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   └── __init__.py                 # Unit tests (per-spiral)
│   ├── integration/
│   │   └── __init__.py                 # Integration tests (Spiral 10)
│   └── security/
│       └── __init__.py                 # Security tests (Spiral 11)
├── docs/
│   ├── spiral_1/
│   │   ├── overview.md                 # This document
│   │   ├── requirements.md             # Functional & non-functional requirements
│   │   ├── architecture.md             # 10+ architecture diagrams (Mermaid)
│   │   ├── architecture_decisions.md   # 10 ADRs with rationale
│   │   ├── database_schema.md          # Complete database schema (SQL + ERD)
│   │   └── testing_strategy.md         # Testing strategy across all spirals
│   ├── threat_model/
│   │   └── threat_model.md             # STRIDE threat model (40+ threats)
│   ├── diagrams/                       # Generated diagram assets
│   ├── spiral_2/ through spiral_12/    # Future spiral documentation
│   └── ...
└── scripts/                            # Build and deployment scripts
```

---

## 6. Hardware Constraints (Phison PS2251-67)

| Constraint | Impact | Mitigation |
|-----------|--------|------------|
| No hardware AES engine | All encryption in software (host CPU) | Use Python `cryptography` library (OpenSSL backend) |
| No firmware signing | Vulnerable to BadUSB | Document as known risk; out of scope for software fix |
| No secure boot | Cannot verify firmware integrity | Software integrity checks on launch |
| USB 2.0 only | ~35 MB/s max throughput | Acceptable for 16 GB drive; chunked I/O |
| NAND wear leveling | Overwritten data may persist in spare blocks | Crypto-shredding instead of physical deletion |
| Proprietary FTL | Cannot control block allocation | Treat as opaque storage; don't rely on physical layout |
| 8051 MCU (80C51) | Limited processing; no custom code viable | All logic in host software |
| Mode 21 dual-partition | Read-only + removable supported natively | Use MPALL to configure Partition A as CD-ROM |

---

## 7. Next Phase Plan — Spiral 2: Cryptographic Prototype

### Objectives
1. Implement `CryptoEngine` class with AES-256-GCM encrypt/decrypt
2. Implement `KDFEngine` class with Argon2id key derivation
3. Implement `KeyManager` class with MEK/KEK wrapping/unwrapping
4. Implement secure memory handling (VirtualLock, SecureZeroMemory)
5. Implement NIST test vector validation
6. Create complete unit test suite with ≥95% coverage

### Deliverables
- `core/crypto/aes_engine.py` — AES-256-GCM operations
- `core/crypto/kdf.py` — Argon2id key derivation
- `core/crypto/key_manager.py` — MEK/KEK lifecycle management
- `core/crypto/secure_memory.py` — Secure memory utilities (Windows)
- `core/crypto/nonce_manager.py` — Nonce generation and tracking
- `tests/unit/test_aes_engine.py` — NIST vector tests + edge cases
- `tests/unit/test_kdf.py` — Parameter validation + output verification
- `tests/unit/test_key_manager.py` — Full key lifecycle tests
- `docs/spiral_2/crypto_design.md` — Cryptographic design document

### Risks for Spiral 2
| Risk | Mitigation |
|------|------------|
| Nonce collision (GCM) | Random 12-byte nonces + uniqueness validation |
| Key material in Python strings (immutable) | Use ctypes buffers + SecureZeroMemory |
| Argon2id performance variance | Benchmark on target hardware; adjustable params |
| Dependency vulnerabilities | Pin versions; audit with `pip-audit` |

### Success Criteria
- [ ] All NIST AES-256-GCM test vectors pass
- [ ] Argon2id produces correct 256-bit keys from passwords
- [ ] MEK can be wrapped and unwrapped with KEK
- [ ] Key material is zeroized after use (verified by memory inspection)
- [ ] Unit test coverage ≥ 95% for `core.crypto`
- [ ] No hardcoded keys, salts, or nonces in source code

---

## Deliverables Checklist

| # | Deliverable | Location | Status |
|---|-------------|----------|--------|
| 1 | Requirements Analysis | `docs/spiral_1/requirements.md` | ✅ |
| 2 | Architecture Diagrams (10) | `docs/spiral_1/architecture.md` | ✅ |
| 3 | Architecture Decision Records (10) | `docs/spiral_1/architecture_decisions.md` | ✅ |
| 4 | STRIDE Threat Model | `docs/threat_model/threat_model.md` | ✅ |
| 5 | Database Schema + ERD | `docs/spiral_1/database_schema.md` | ✅ |
| 6 | Testing Strategy | `docs/spiral_1/testing_strategy.md` | ✅ |
| 7 | Project Configuration | `config/default_config.json` | ✅ |
| 8 | Directory Structure | Complete tree with `__init__.py` | ✅ |
| 9 | Hardware Analysis | This document (Section 6) | ✅ |
| 10 | Spiral 2 Plan | This document (Section 7) | ✅ |

---

## Approval Gate

> **Spiral 1 is complete and ready for review.**
> 
> Before proceeding to Spiral 2 (Cryptographic Prototype), please review:
> 1. All requirements for completeness and accuracy
> 2. Threat model for missing attack vectors
> 3. Architecture decisions for any concerns
> 4. Database schema for data model correctness
> 5. Testing strategy for coverage gaps
> 
> **Approval required before Spiral 2 implementation begins.**

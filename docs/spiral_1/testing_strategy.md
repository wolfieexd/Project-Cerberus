# Spiral 1 — Testing Strategy

## Overview

This document defines the comprehensive testing strategy for the FORTRESS-USB project
across all spiral phases. Each spiral phase will include specific test implementations
that align with this master testing plan.

---

## Testing Philosophy

### Guiding Principles

1. **Security-First Testing**: Every module must be tested for both correct functionality 
   AND resistance to attack vectors identified in the threat model.
2. **Defense in Depth**: Tests verify that individual security controls work correctly AND
   that layered defenses provide compound protection.
3. **Tamper Resistance**: Tests must verify that security state cannot be manipulated through
   USB removal, power cycling, clock manipulation, or file modification.
4. **Cryptographic Correctness**: All crypto operations must be tested against known-answer
   vectors from NIST and verified for proper key handling/zeroization.

### Test Pyramid

```
                    ┌─────────────────┐
                    │   Penetration   │  ← Spiral 11
                    │     Tests       │
                   ┌┴─────────────────┴┐
                   │   Integration     │  ← Spirals 10-11
                   │     Tests         │
                  ┌┴───────────────────┴┐
                  │    Component        │  ← Each Spiral
                  │      Tests         │
                 ┌┴─────────────────────┴┐
                 │       Unit Tests       │  ← Each Spiral
                 └────────────────────────┘
```

---

## Test Categories

### 1. Unit Tests

**Scope**: Individual functions and classes in isolation.  
**Framework**: `pytest` with `pytest-cov` for coverage.  
**Coverage Target**: ≥ 90% line coverage, ≥ 85% branch coverage for security-critical modules.

| Module | Test File | Key Tests |
|--------|-----------|-----------|
| `core.crypto.aes_engine` | `tests/unit/test_aes_engine.py` | NIST vectors, nonce uniqueness, key zeroization |
| `core.crypto.kdf` | `tests/unit/test_kdf.py` | Argon2id parameter validation, salt generation, output length |
| `core.crypto.key_manager` | `tests/unit/test_key_manager.py` | MEK/KEK lifecycle, wrapping/unwrapping, key rotation |
| `core.auth.authenticator` | `tests/unit/test_authenticator.py` | Password validation, attempt counting, lockout logic |
| `core.timer.persistent_timer` | `tests/unit/test_persistent_timer.py` | Countdown accuracy, state persistence, resume from saved |
| `core.timer.anti_tamper` | `tests/unit/test_anti_tamper.py` | HMAC validation, clock manipulation detection |
| `core.forensics.collector` | `tests/unit/test_forensic_collector.py` | System info collection, log integrity |
| `core.forensics.logger` | `tests/unit/test_forensic_logger.py` | Hash chain validation, tamper detection |
| `core.shredding.shred_engine` | `tests/unit/test_shred_engine.py` | Key destruction, verification, state transitions |
| `core.storage.vault` | `tests/unit/test_vault.py` | File encrypt/decrypt, chunk handling, index management |
| `trusted.device_manager` | `tests/unit/test_device_manager.py` | Fingerprint generation, device registration, lookup |
| `gui.controllers` | `tests/unit/test_gui_controllers.py` | Screen transitions, timer display, error handling |

### 2. Component Tests

**Scope**: Module-level integration within a single component.  
**Framework**: `pytest` with mocking for external dependencies.

| Component | Test File | Key Tests |
|-----------|-----------|-----------|
| Crypto Subsystem | `tests/integration/test_crypto_subsystem.py` | Full encrypt → store → retrieve → decrypt flow |
| Auth Subsystem | `tests/integration/test_auth_subsystem.py` | Password → KDF → KEK → unwrap MEK → verify |
| Timer Subsystem | `tests/integration/test_timer_subsystem.py` | Start → pause → serialize → deserialize → resume |
| Forensic Subsystem | `tests/integration/test_forensic_subsystem.py` | Collect → log → verify chain → survive shred |

### 3. Integration Tests

**Scope**: Cross-module interactions and end-to-end workflows.  
**Framework**: `pytest` with temporary file systems and mock USB devices.

| Scenario | Test File | Description |
|----------|-----------|-------------|
| Full Unlock | `tests/integration/test_full_unlock.py` | USB insert → timer start → auth → unlock → access |
| Failed Auth Cascade | `tests/integration/test_failed_auth.py` | 3 failures → forensic log → crypto-shred → verify destroyed |
| Timer Expiry | `tests/integration/test_timer_expiry.py` | Timer countdown → expiry → forensic log → crypto-shred |
| USB Removal/Reinsertion | `tests/integration/test_usb_lifecycle.py` | Insert → partial timer → remove → reinsert → verify state |
| Trusted Device | `tests/integration/test_trusted_device.py` | Register → remove USB → reinsert on same host → auto-unlock |
| Crypto-Shred Verification | `tests/integration/test_shred_verify.py` | Shred → attempt decrypt → verify failure → verify forensics |

### 4. Security Tests

**Scope**: Adversarial testing targeting specific threat model entries.  
**Framework**: `pytest` with custom security fixtures.

| Attack Vector | Test File | Description |
|---------------|-----------|-------------|
| Timer Reset | `tests/security/test_timer_attacks.py` | Attempt to reset timer via file modification, clock change |
| Counter Reset | `tests/security/test_counter_attacks.py` | Attempt to reset attempt counter via DB modification |
| Key Extraction | `tests/security/test_key_extraction.py` | Verify keys cannot be extracted from state files |
| HMAC Bypass | `tests/security/test_hmac_bypass.py` | Modify protected fields, verify HMAC validation catches it |
| Nonce Reuse | `tests/security/test_nonce_reuse.py` | Verify nonce uniqueness across all encryption operations |
| Memory Residue | `tests/security/test_memory_cleanup.py` | Verify key material is zeroized after use |
| State File Tampering | `tests/security/test_state_tampering.py` | Modify system.db, verify system detects tampering |
| Downgrade Attack | `tests/security/test_downgrade.py` | Attempt to weaken Argon2id parameters |
| Replay Attack | `tests/security/test_replay.py` | Replay old valid authentication tokens |
| Race Condition | `tests/security/test_race_conditions.py` | Concurrent timer/auth operations |

### 5. Penetration Tests (Spiral 11)

**Scope**: Full adversarial assessment of the complete system.  
**Methodology**: OWASP Testing Guide adapted for desktop applications.

| Test | Description | Tool |
|------|-------------|------|
| Firmware Analysis | Dump and analyze USB controller behavior | Custom scripts |
| Binary Analysis | Reverse engineer unlock.exe for hardcoded secrets | Ghidra, strings |
| File System Analysis | Examine raw disk for key material leaks | Autopsy, FTK |
| Memory Forensics | Dump process memory for key material | Volatility, Process Hacker |
| API Hooking | Intercept crypto library calls | Frida, API Monitor |
| Debug Attachment | Attach debugger to running process | x64dbg, WinDbg |
| DLL Injection | Inject code to extract keys from running process | Custom DLL |
| USB Emulation | Emulate USB device to bypass authentication | USBProxy, Facedancer |
| Clock Manipulation | Change system clock to reset timer | System settings |
| Disk Cloning | Clone USB to reset state | dd, FTK Imager |

---

## Test Infrastructure

### Test Configuration

```python
# tests/conftest.py

import pytest
import tempfile
import os

@pytest.fixture
def temp_vault(tmp_path):
    """Create a temporary vault directory structure for testing."""
    vault_dir = tmp_path / ".vault"
    vault_dir.mkdir()
    (vault_dir / "data").mkdir()
    (vault_dir / "chunks").mkdir()
    return vault_dir

@pytest.fixture
def temp_system_dir(tmp_path):
    """Create a temporary system directory for testing."""
    sys_dir = tmp_path / ".fortress"
    sys_dir.mkdir()
    return sys_dir

@pytest.fixture
def test_password():
    """Standard test password."""
    return "TestP@ssw0rd!2024"

@pytest.fixture
def test_salt():
    """Deterministic test salt for reproducible KDF output."""
    return bytes.fromhex("0123456789abcdef0123456789abcdef")

@pytest.fixture
def mock_system_info():
    """Mock system information for forensic tests."""
    return {
        "hostname": "TEST-WORKSTATION",
        "username": "test_user",
        "machine_uuid": "12345678-1234-1234-1234-123456789ABC",
        "motherboard_serial": "TEST-MB-SERIAL-001",
        "windows_sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
        "ip_addresses": ["192.168.1.100"],
        "os_info": "Windows 11 Pro 23H2 Build 22631",
    }
```

### Test Data Management

```python
# tests/test_vectors.py

"""
NIST AES-256-GCM Test Vectors
Source: NIST SP 800-38D, GCM Specification

These vectors are used to validate the correctness of the AES-256-GCM 
implementation against known-good reference values.
"""

AES_256_GCM_VECTORS = [
    {
        "description": "NIST Test Case 13 — AES-256-GCM, 96-bit IV",
        "key": bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "iv": bytes.fromhex("000000000000000000000000"),
        "plaintext": b"",
        "aad": b"",
        "ciphertext": b"",
        "tag": bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"),
    },
    {
        "description": "NIST Test Case 14 — AES-256-GCM, 96-bit IV, plaintext",
        "key": bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "iv": bytes.fromhex("000000000000000000000000"),
        "plaintext": bytes.fromhex("00000000000000000000000000000000"),
        "aad": b"",
        "ciphertext": bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
        "tag": bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"),
    },
]
```

### CI/CD Pipeline

```yaml
# .github/workflows/test.yml (for reference — actual CI may differ)
name: FORTRESS-USB Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements-dev.txt
      - run: pytest tests/unit/ -v --cov=secure_usb --cov-report=html
      - run: pytest tests/integration/ -v
      - run: pytest tests/security/ -v --timeout=120
```

---

## Coverage Requirements by Spiral

| Spiral | Module | Min Line Coverage | Min Branch Coverage |
|--------|--------|-------------------|---------------------|
| 2 | `core.crypto` | 95% | 90% |
| 3 | `core.storage` | 90% | 85% |
| 4 | `core.auth` | 95% | 90% |
| 5 | `trusted` | 85% | 80% |
| 6 | `core.timer` | 95% | 90% |
| 7 | `core.forensics` | 90% | 85% |
| 8 | `core.shredding` | 95% | 90% |
| 9 | `gui` | 80% | 75% |
| 10 | Overall | 90% | 85% |

---

## Test Execution Schedule

| Phase | Frequency | Tests |
|-------|-----------|-------|
| Development | Every commit | Unit tests (affected modules) |
| Pre-merge | Every PR | Full unit + integration suite |
| Nightly | Daily | Full suite + security tests |
| Release | Per release | Full suite + penetration tests |

---

## Test Reporting

### Metrics Collected

- Pass/fail counts per category
- Code coverage percentages
- Security test results
- Performance benchmarks (KDF timing, encrypt/decrypt throughput)
- Memory usage (peak, key material exposure windows)

### Report Format

```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "spiral": 2,
    "results": {
        "unit": {"passed": 45, "failed": 0, "skipped": 2},
        "integration": {"passed": 12, "failed": 0, "skipped": 0},
        "security": {"passed": 8, "failed": 0, "skipped": 1},
        "coverage": {
            "line": 94.2,
            "branch": 88.7
        },
        "performance": {
            "kdf_time_ms": 1250,
            "encrypt_1mb_ms": 8.3,
            "decrypt_1mb_ms": 7.9
        }
    }
}
```

---

## Risk-Based Test Prioritization

### Critical Priority (Must pass before any release)

1. ✅ MEK/KEK encryption/decryption correctness
2. ✅ Argon2id parameter enforcement
3. ✅ Timer persistence across USB removal
4. ✅ Attempt counter persistence across USB removal
5. ✅ Crypto-shredding completeness (no residual key material)
6. ✅ HMAC integrity validation on all state files
7. ✅ Nonce uniqueness guarantee

### High Priority

1. ✅ Trusted device fingerprint accuracy
2. ✅ Forensic log chain integrity
3. ✅ Large file chunked encryption correctness
4. ✅ GUI screen transition correctness
5. ✅ Error handling for all failure modes

### Medium Priority

1. ✅ Performance within acceptable bounds
2. ✅ Memory cleanup verification
3. ✅ Configuration validation
4. ✅ Edge cases (zero-byte files, max-size files, special characters)

### Low Priority

1. ✅ UI visual regression
2. ✅ Cross-version compatibility
3. ✅ Documentation accuracy

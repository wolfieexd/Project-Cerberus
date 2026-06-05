# Spiral 1 — Security Architecture Decisions

## Decision Log

This document records all architectural decisions made during Spiral 1,
with rationale, alternatives considered, and risk implications.

---

## AD-001: Software-Only Security Architecture

### Context
The Phison PS2251-67 controller has **no hardware encryption engine**, **no firmware signing**, 
and **no secure boot**. Custom firmware for the -67 variant is impractical (Psychson only 
supports PS2251-03).

### Decision
Implement ALL security functionality in software running on the host machine, while 
preserving the architecture for future migration to hardware-backed security.

### Rationale
1. Controller firmware modification is not viable for PS2251-67
2. Software implementation allows rapid prototyping and iteration
3. Architecture can be ported to hardware-backed controllers (PS2251-33/50) later
4. Software approach is independent of USB controller capabilities

### Consequences
- **Positive**: Portable, testable, maintainable, controller-agnostic
- **Negative**: Keys exist in host RAM (vulnerable to memory forensics), no hardware 
  tamper resistance, security dependent on host OS integrity
- **Mitigation**: Minimize key exposure window, use `VirtualLock()` and 
  `SecureZeroMemory()`, consider TPM for key sealing

### Alternatives Rejected
| Alternative | Rejection Reason |
|-------------|-----------------|
| Custom firmware (Psychson) | Not viable for PS2251-67; bricking risk |
| Hardware AES controller | Requires different controller (PS2251-33/50); out of scope |
| Full disk encryption (BitLocker To Go) | No custom security policies; no timer/shredding |

---

## AD-002: AES-256-GCM Over AES-256-XTS

### Context
Industry standard for full-disk encryption is AES-256-XTS (used by BitLocker, LUKS, 
IronKey). However, our system encrypts individual files, not raw disk sectors.

### Decision
Use AES-256-GCM (Galois/Counter Mode) for all encryption operations.

### Rationale
1. **Authenticated encryption**: GCM provides integrity AND confidentiality. XTS provides 
   only confidentiality — tampered ciphertext decrypts silently to garbage.
2. **File-level granularity**: We encrypt individual files and key blobs, not raw sectors.
   GCM is designed for this use case.
3. **Tamper detection**: The 128-bit authentication tag lets us detect any modification to 
   encrypted data, which is critical for detecting offline tampering.
4. **NIST approved**: SP 800-38D standardizes GCM. AES-GCM is the de facto standard for 
   TLS 1.3, IPsec, and modern protocols.

### Consequences
- **Positive**: Tamper detection, AEAD, widely supported, well-analyzed
- **Negative**: Slightly more storage overhead (12-byte nonce + 16-byte tag per encryption), 
  catastrophic nonce reuse vulnerability
- **Mitigation**: Strict nonce management (random 12-byte nonce per operation, nonce 
  tracking in database)

### Critical Warning: Nonce Reuse
> **GCM with nonce reuse is CATASTROPHICALLY broken.** Reusing a nonce with the same key
> reveals the authentication key (GHASH key H) and allows forgeries. Our implementation
> MUST guarantee nonce uniqueness through random generation and database tracking.

---

## AD-003: Argon2id with Aggressive Parameters

### Context
Need a password-based KDF to derive the Key Encryption Key (KEK). USB unlock is a 
low-frequency operation (once per session), so high computational cost is acceptable.

### Decision
Use Argon2id with: `memory=256 MiB, time_cost=4, parallelism=8, hash_len=32`.

### Rationale
1. **Argon2id** is the PHC (Password Hashing Competition) winner and recommended by OWASP
2. **Hybrid resistance**: Argon2id combines Argon2i (side-channel resistant) and Argon2d 
   (GPU/ASIC resistant)
3. **256 MiB memory**: Makes GPU-based attacks extremely expensive (~$100M+ for 
   reasonable throughput)
4. **Single-use operation**: Unlock happens once per session; 1-2 second KDF time is acceptable
5. **NIST alignment**: SP 800-132 recommends memory-hard functions for password-based KDF

### Parameters Table

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `type` | Argon2id | Hybrid side-channel + GPU resistance |
| `memory_cost` | 262,144 KiB (256 MiB) | Exceeds OWASP "High Security" recommendation |
| `time_cost` | 4 | Multiple passes for time-memory tradeoff |
| `parallelism` | 8 | Utilizes modern multi-core CPUs |
| `hash_len` | 32 bytes | 256-bit output for AES-256 key |
| `salt_len` | 16 bytes | 128-bit random salt (NIST minimum) |

### Consequences
- **Positive**: State-of-the-art brute-force resistance; future-proof
- **Negative**: 1-2 second unlock delay; 256 MiB RAM requirement during KDF
- **Mitigation**: Display progress indicator during KDF; verify minimum RAM availability

---

## AD-004: Two-Database Architecture

### Context
Need to persist both security state (timer, attempts) and cryptographic material (keys, 
encrypted file index). These have fundamentally different lifecycle and security requirements.

### Decision
Use two separate SQLite databases:
- `system.db` on Partition A (security state)
- `vault.db` on Partition B (cryptographic material)

### Rationale
1. **Separation of concerns**: Security state (timer, counters) must survive crypto-shredding;
   key material must be destroyable
2. **Tamper isolation**: Partition A is conceptually read-only to users; modification of 
   `system.db` requires elevated privileges or physical access
3. **Forensic survivability**: Forensic evidence in `vault.db` uses a separate HMAC key 
   that survives MEK destruction
4. **Recovery model**: After crypto-shredding, `system.db` still functions for audit purposes

### Alternatives Rejected
| Alternative | Rejection Reason |
|-------------|-----------------|
| Single database | Timer/counter state would be destroyed during crypto-shredding |
| File-based state (JSON/TOML) | No ACID guarantees; harder to maintain integrity |
| Encrypted SQLite (SQLCipher) | Adds dependency; key management complexity; can't access if shredded |

---

## AD-005: HMAC-Based Anti-Tamper for State Files

### Context
An attacker with physical access to the USB drive could modify `system.db` to reset the 
timer or attempt counter, bypassing security controls.

### Decision
Protect all mutable state with HMAC-SHA256 using a device-derived key.

### Rationale
1. **Tamper detection**: Any modification to protected fields invalidates the HMAC
2. **Device binding**: HMAC key derived from device-specific secret prevents cross-device 
   state transplantation
3. **Lightweight**: HMAC computation is near-instantaneous
4. **Hash chain for logs**: Audit log entries form a Merkle-like chain, making insertion/
   deletion detectable

### HMAC Key Derivation
```
hmac_key = HKDF-SHA256(
    ikm = vault_uuid || device_serial,
    salt = "FORTRESS-HMAC-v1",
    info = "state-integrity",
    length = 32
)
```

### Consequences
- **Positive**: Detects all state file modifications; lightweight; proven construct
- **Negative**: If HMAC key is extracted, attacker can forge valid states
- **Mitigation**: Derive HMAC key from multiple device-specific values; minimize key exposure

---

## AD-006: Crypto-Shredding Over Secure Deletion

### Context
Need to make data irrecoverable when security conditions are violated (timer expiry, 
max attempts). On flash storage, traditional secure deletion (overwrite with zeros/random) 
is unreliable due to wear leveling.

### Decision
Destroy only cryptographic keys (MEK, KEK, key container). Leave encrypted data intact.

### Rationale
1. **Flash storage limitation**: Wear leveling means overwritten data may persist in spare 
   blocks. Even DoD 5220.22-M multi-pass overwrite cannot guarantee data destruction on 
   flash media.
2. **Crypto-shredding is definitive**: Without the MEK, AES-256-GCM encrypted data is 
   computationally infeasible to recover (2^256 brute force required)
3. **Speed**: Destroying a 32-byte key is instantaneous vs. overwriting 16 GB of data
4. **Forensic compatibility**: Encrypted data remains as evidence; only access is destroyed
5. **Industry standard**: IronKey, Kingston, Apricorn all use this approach

### Destruction Protocol
```
1. Overwrite wrapped_mek in vault.db with os.urandom(len(wrapped_mek))  [3 passes]
2. Overwrite kek_salt in vault.db with os.urandom(16)                    [3 passes]
3. Overwrite verification_ct with os.urandom(len(verification_ct))       [3 passes]
4. DELETE FROM key_container
5. VACUUM vault.db                                                        [Reclaim pages]
6. Set key_state = 'DESTROYED' in new row
7. Flush to disk (fsync)
8. Verify: attempt to read wrapped_mek → must fail
9. Log destruction event in system_audit_log
```

### Consequences
- **Positive**: Instant, reliable, flash-safe, forensically sound
- **Negative**: If MEK was somehow leaked/backed up externally, data remains recoverable
- **Mitigation**: Never export MEK; minimize MEK exposure window in RAM

---

## AD-007: Persistent Timer Using Database + Monotonic Clock

### Context
The countdown timer (120 seconds) must not reset when the USB is unplugged. It must 
continue from where it left off across reboots, power loss, and USB reinsertion.

### Decision
Store timer state in `system.db` with the remaining milliseconds, protected by HMAC. 
On USB removal, immediately persist current state. On reinsertion, validate HMAC and 
resume from persisted state.

### Approach
```
INSERT:
  remaining_ms = 120000
  last_tick_at = NOW()
  is_running = 1

TICK (every 100ms):
  elapsed = NOW() - last_tick_at
  remaining_ms -= elapsed
  last_tick_at = NOW()
  if remaining_ms <= 0: TRIGGER SHRED

USB REMOVAL EVENT:
  Persist remaining_ms to system.db
  Update HMAC
  is_running = 0

USB INSERTION:
  Read remaining_ms from system.db
  Validate HMAC
  Resume countdown from remaining_ms
  is_running = 1
```

### Anti-Tamper Measures
1. **HMAC protection**: Timer state HMAC prevents direct value modification
2. **Monotonic reference**: Use `time.monotonic()` for tick calculations (immune to wall 
   clock changes) during a single session
3. **Reasonable elapsed check**: On reinsertion, if `NOW() - last_tick_at > remaining_ms`, 
   trigger immediate shred (timer would have expired while disconnected)
4. **No reset path**: There is NO API, function, or code path to reset the timer to 120s 
   once it has started. Reset requires re-initialization (full setup wizard).

### Consequences
- **Positive**: Timer survives all physical manipulation; simple and robust
- **Negative**: Clock manipulation on host could theoretically affect wall-clock checks
- **Mitigation**: Cross-reference monotonic clock; flag suspicious time jumps

---

## AD-008: Machine Fingerprinting for Trusted Host

### Context
Need to identify trusted workstations for automatic unlock. Must be stable across reboots 
but change if hardware is replaced.

### Decision
Composite fingerprint using SHA-256 hash of: System UUID + Motherboard Serial + Windows SID.

### Fingerprint Composition
```python
components = [
    system_uuid,        # SMBIOS/DMI System UUID (stable across OS reinstalls)
    motherboard_serial, # Baseboard serial (hardware-bound)
    windows_sid,        # User SID (OS + user identity binding)
]
fingerprint = SHA-256("|".join(components))
```

### Why These Specific Identifiers

| Identifier | Stability | Uniqueness | Why Included |
|------------|-----------|------------|--------------|
| System UUID | Very High (hardware-burned) | Very High | Identifies physical machine |
| Motherboard Serial | Very High (hardware-burned) | High | Prevents VM cloning attacks |
| Windows SID | High (survives updates) | High | Binds to specific user account |

### Optional Enhancement: TPM Binding
If TPM 2.0 is available, additionally seal a device-specific KEK to PCR values. This 
provides hardware-backed assurance that the system hasn't been tampered with.

### Consequences
- **Positive**: Stable, unique, hardware-bound identification
- **Negative**: May break if user replaces motherboard or reinstalls Windows
- **Mitigation**: Allow re-registration of trusted devices (requires password authentication)

---

## AD-009: PyInstaller Single-File Packaging

### Context
The unlock.exe launcher must run from the USB drive's read-only partition without 
requiring Python installation on the host.

### Decision
Package the application using PyInstaller in single-file mode (`--onefile`).

### Rationale
1. **No dependencies**: User doesn't need Python installed
2. **Portable**: Single .exe runs from USB drive
3. **Self-contained**: All libraries (PySide6, cryptography, argon2-cffi) bundled
4. **Windows-native**: Looks like a standard Windows application

### Build Configuration
```
pyinstaller \
    --onefile \
    --windowed \
    --name unlock \
    --icon assets/icon.ico \
    --add-data "config;config" \
    --hidden-import argon2 \
    --hidden-import PySide6.QtWidgets \
    secure_usb/main.py
```

### Consequences
- **Positive**: Simple deployment; no installation required
- **Negative**: Large executable (~50-100 MB with PySide6); slow first launch (extraction)
- **Mitigation**: Use `--onedir` for faster launch if acceptable; splash screen during load

---

## AD-010: Forensic Evidence Survives Crypto-Shredding

### Context
When crypto-shredding is triggered, we want the forensic evidence (who was using the 
device, when, from where) to remain accessible for investigation.

### Decision
Forensic evidence uses a separate HMAC key that is NOT derived from the MEK/KEK chain. 
The forensic evidence table remains readable after crypto-shredding.

### Rationale
1. **Investigation support**: After a security incident, investigators need to know who 
   triggered the destruction
2. **Legal compliance**: Some jurisdictions require retention of access logs
3. **Separate key chain**: Forensic HMAC key derived from vault_uuid + device constant, 
   independent of user password

### Consequences
- **Positive**: Evidence survives destruction; supports incident response
- **Negative**: Forensic data reveals some metadata about the security event
- **Mitigation**: Forensic data contains system info, not file contents; encrypted user 
  data remains encrypted (and inaccessible)

---

## Decision Matrix Summary

| ID | Decision | Risk Level | Reversible? |
|----|----------|------------|-------------|
| AD-001 | Software-only architecture | High | Yes (migrate to HW later) |
| AD-002 | AES-256-GCM over XTS | Medium | No (data format change) |
| AD-003 | Argon2id aggressive params | Low | Yes (parameter tuning) |
| AD-004 | Two-database architecture | Medium | No (schema restructure) |
| AD-005 | HMAC anti-tamper | Low | Yes (algorithm swap) |
| AD-006 | Crypto-shredding over deletion | Low | No (core design) |
| AD-007 | Persistent timer in DB | Medium | No (core feature) |
| AD-008 | Composite machine fingerprint | Medium | Yes (add/remove factors) |
| AD-009 | PyInstaller single-file | Low | Yes (change packager) |
| AD-010 | Forensic evidence survives shred | Low | Yes (separate key) |

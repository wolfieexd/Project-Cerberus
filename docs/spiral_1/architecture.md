# FORTRESS-USB — Architecture Documentation

> **Project:** Advanced Self-Protecting Encrypted Removable USB Storage System
> **Classification:** CONFIDENTIAL — Internal Engineering Use Only
> **Revision:** 1.0.0 · Spiral 1
> **Last Updated:** 2026-06-02

---

## Table of Contents

1. [System Context Diagram (C4 Level 1)](#1-system-context-diagram-c4-level-1)
2. [Container Diagram (C4 Level 2)](#2-container-diagram-c4-level-2)
3. [Component Diagram (C4 Level 3)](#3-component-diagram-c4-level-3)
4. [Key Hierarchy Diagram](#4-key-hierarchy-diagram)
5. [Data Flow Diagram (DFD)](#5-data-flow-diagram-dfd)
6. [Sequence Diagrams](#6-sequence-diagrams)
7. [State Machine Diagram](#7-state-machine-diagram)
8. [Deployment Diagram](#8-deployment-diagram)
9. [Class Diagram](#9-class-diagram)
10. [Physical Partition Layout Diagram](#10-physical-partition-layout-diagram)

---

## 1. System Context Diagram (C4 Level 1)

The System Context diagram establishes the highest-level view of FORTRESS-USB. It identifies the system boundary, all external actors, and the nature of every interaction that crosses that boundary. This is the starting point for all downstream architectural reasoning.

**External Actors:**

| Actor | Type | Trust Level |
|---|---|---|
| Authorized User | Human | Trusted (after authentication) |
| Host Machine | System | Semi-Trusted (unknown environment) |
| USB Physical Drive | Hardware | Trusted (tamper-evident) |
| Adversary | Human/System | Untrusted |

```mermaid
C4Context
    title FORTRESS-USB — System Context Diagram (C4 Level 1)

    Person(user, "Authorized User", "Possesses the unlock password and/or is registered as a trusted device owner")
    Person_Ext(adversary, "Adversary", "Unauthorized actor attempting data exfiltration, brute-force, or physical theft")

    System_Boundary(fortress, "FORTRESS-USB System") {
        System(fortressCore, "FORTRESS-USB", "Self-protecting encrypted USB storage system with countdown-based crypto-shredding, forensic logging, and trusted-device auto-unlock")
    }

    System_Ext(hostMachine, "Host Machine", "Windows PC where the USB drive is inserted; runs the unlock application and hosts the mounted encrypted volume")
    System_Ext(usbDrive, "USB Physical Drive", "Removable USB 3.x flash storage with dual-partition layout: read-only launcher + encrypted vault")
    System_Ext(tpmChip, "TPM 2.0 Module", "Trusted Platform Module on the host machine providing hardware-bound key sealing and platform attestation")

    Rel(user, fortressCore, "Enters password, manages files, configures timer", "PySide6 GUI")
    Rel(fortressCore, hostMachine, "Mounts encrypted volume, reads host fingerprint", "Win32 API / WMI")
    Rel(fortressCore, usbDrive, "Reads Partition A launcher, reads/writes Partition B encrypted vault", "USB 3.x / SCSI")
    Rel(fortressCore, tpmChip, "Seals/unseals trusted-device keys", "TPM 2.0 TSS")
    Rel(adversary, fortressCore, "Brute-force attempts, physical theft, forensic imaging", "Physical / Digital")
    Rel(adversary, usbDrive, "Physical extraction, bus sniffing", "Physical Access")

    UpdateRelStyle(adversary, fortressCore, $textColor="red", $lineColor="red")
    UpdateRelStyle(adversary, usbDrive, $textColor="red", $lineColor="red")
```

**Key Design Decisions at This Level:**

- The system boundary encapsulates *both* the on-device components (Partition A/B) and the host-side application. Neither operates independently.
- The TPM is an optional external dependency — the system degrades gracefully to password-only mode when unavailable.
- The adversary model includes both remote (brute-force via host) and physical (stolen drive) attack vectors.

---

## 2. Container Diagram (C4 Level 2)

The Container diagram decomposes the FORTRESS-USB system boundary into its four major deployable containers. Each container is an independently addressable runtime unit with clear responsibilities, interfaces, and data ownership.

```mermaid
C4Container
    title FORTRESS-USB — Container Diagram (C4 Level 2)

    Person(user, "Authorized User", "Authenticates via password or trusted device")

    System_Boundary(fortress, "FORTRESS-USB System") {

        Container_Boundary(partA, "Partition A — Read-Only Launcher") {
            Container(unlockExe, "unlock.exe", "PyInstaller Bundle", "Frozen Python application; auto-launched on USB insertion; bootstraps the host application")
            Container(configFiles, "config.yaml", "YAML", "Public system configuration: timer defaults, UI theme, branding, version metadata")
            Container(sysMeta, "system.meta", "Binary", "System metadata: partition UUIDs, format version, creation timestamp, integrity HMAC")
        }

        Container_Boundary(partB, "Partition B — Encrypted Storage") {
            Container(encData, "Encrypted User Data", "AES-256-GCM Blobs", "User files encrypted individually with per-file nonces under the MEK")
            Container(encMeta, "Encrypted Metadata", "AES-256-GCM", "File index, directory tree, timestamps — all encrypted under MEK")
            Container(forensicLog, "Forensic Log", "Append-Only Encrypted", "Tamper-evident log of all access attempts, host fingerprints, and security events")
            Container(keyContainer, "Encrypted Key Container", "JSON + Binary", "Wrapped MEK blob, Argon2id salt, KDF parameters, key version counter")
            Container(timerState, "Timer State", "Encrypted Binary", "Persistent countdown value, last-tick timestamp, serialization nonce")
        }

        Container(hostApp, "Host Application", "PySide6 / Python 3.12", "Full GUI running on the host machine: unlock screen, file browser, countdown display, settings panel")
        Container(coreEngine, "Core Engine", "Python Modules", "Cryptographic operations, storage I/O, authentication logic, timer management, forensic logging, and crypto-shredding")
    }

    System_Ext(hostOS, "Host Operating System", "Windows 10/11 — provides USB detection, volume mounting, WMI, and TPM access")

    Rel(user, hostApp, "Interacts via GUI", "Mouse / Keyboard")
    Rel(hostApp, coreEngine, "Invokes engine APIs", "Python function calls")
    Rel(coreEngine, unlockExe, "Bootstrapped from", "Process launch")
    Rel(coreEngine, configFiles, "Reads configuration", "File I/O — read-only")
    Rel(coreEngine, sysMeta, "Validates system integrity", "HMAC verification")
    Rel(coreEngine, encData, "Encrypts/Decrypts user files", "AES-256-GCM")
    Rel(coreEngine, encMeta, "Reads/Writes file metadata", "AES-256-GCM")
    Rel(coreEngine, forensicLog, "Appends security events", "Append-only write")
    Rel(coreEngine, keyContainer, "Unwraps/Wraps MEK", "AES-KW + Argon2id")
    Rel(coreEngine, timerState, "Persists countdown", "Encrypted R/W")
    Rel(coreEngine, hostOS, "USB detection, volume mount, WMI queries, TPM calls", "Win32 API")
```

**Container Responsibilities:**

| Container | Primary Responsibility | Data Ownership |
|---|---|---|
| Partition A (Read-Only) | Bootstrap, public config, integrity anchor | `unlock.exe`, `config.yaml`, `system.meta` |
| Partition B (Encrypted) | Secure vault for all sensitive data | Encrypted blobs, key container, logs, timer |
| Host Application | User-facing GUI and interaction layer | Transient UI state only (nothing persisted on host) |
| Core Engine | All security-critical business logic | In-memory keys, session state |

> **Critical Invariant:** No sensitive data (keys, plaintext, passwords) is *ever* persisted on the host machine. All persistence is on Partition B.

---

## 3. Component Diagram (C4 Level 3)

The Component diagram provides the deepest structural view, decomposing the Core Engine container into its constituent modules. Each module is a cohesive unit of functionality with explicitly defined interfaces.

```mermaid
C4Component
    title FORTRESS-USB — Core Engine Component Diagram (C4 Level 3)

    Container_Boundary(engine, "Core Engine") {

        Component(cryptoEngine, "CryptoEngine", "Python Module", "AES-256-GCM encrypt/decrypt, Argon2id KDF, AES-KW key wrapping/unwrapping, nonce generation, constant-time comparison")
        Component(keyManager, "KeyManager", "Python Module", "MEK lifecycle management, KEK derivation orchestration, key rotation, secure memory zeroization")
        Component(storageManager, "StorageManager", "Python Module", "Encrypted file I/O, partition detection and mounting, blob read/write, metadata index management")
        Component(authManager, "AuthManager", "Python Module", "Password validation against stored verifier, attempt counter with lockout, rate limiting, brute-force detection")
        Component(timerEngine, "TimerEngine", "Python Module", "Persistent monotonic countdown, state serialization/deserialization, tick callbacks, expiration event emission")
        Component(forensicLogger, "ForensicLogger", "Python Module", "Host fingerprint collection via WMI, structured security event logging, append-only integrity chain, log encryption")
        Component(shreddingEngine, "ShreddingEngine", "Python Module", "MEK/KEK memory zeroization, key container file overwrite and deletion, destruction verification, point-of-no-return enforcement")
        Component(trustedDeviceMgr, "TrustedDeviceManager", "Python Module", "Machine fingerprint generation from hardware IDs, TPM 2.0 key sealing/unsealing, trusted device registry, auto-unlock orchestration")
        Component(guiController, "GUIController", "PySide6 Module", "Screen management: splash, unlock, countdown, file browser, settings, destruction confirmation; signal/slot event binding")
        Component(configManager, "ConfigManager", "Python Module", "YAML configuration loading, schema validation, default value injection, runtime parameter access")
    }

    Rel(guiController, authManager, "Submits password for validation")
    Rel(guiController, timerEngine, "Reads countdown, receives tick signals")
    Rel(guiController, storageManager, "Requests file listing and file operations")
    Rel(guiController, configManager, "Reads UI and system configuration")

    Rel(authManager, cryptoEngine, "Invokes Argon2id for password verification")
    Rel(authManager, keyManager, "Triggers KEK derivation on successful auth")
    Rel(authManager, forensicLogger, "Logs auth attempts — success and failure")
    Rel(authManager, shreddingEngine, "Triggers crypto-shred on max attempt breach")

    Rel(keyManager, cryptoEngine, "Delegates all cryptographic primitives")
    Rel(keyManager, storageManager, "Reads/writes wrapped MEK from key container")

    Rel(storageManager, cryptoEngine, "Encrypts/decrypts file blobs and metadata")

    Rel(timerEngine, shreddingEngine, "Triggers crypto-shred on expiration")
    Rel(timerEngine, storageManager, "Persists timer state to Partition B")
    Rel(timerEngine, forensicLogger, "Logs timer events: start, pause, expire")

    Rel(shreddingEngine, keyManager, "Commands MEK/KEK destruction")
    Rel(shreddingEngine, storageManager, "Overwrites key container file on disk")
    Rel(shreddingEngine, forensicLogger, "Logs destruction event with verification hash")

    Rel(trustedDeviceMgr, cryptoEngine, "Encrypts/decrypts device registry entries")
    Rel(trustedDeviceMgr, keyManager, "Provides auto-unwrapped MEK on trusted match")
    Rel(trustedDeviceMgr, forensicLogger, "Logs trusted device match/mismatch events")

    Rel(forensicLogger, cryptoEngine, "Encrypts log entries before append")
    Rel(forensicLogger, storageManager, "Writes encrypted log to Partition B")
```

### Module Interface Summary

| Module | Key Public Methods | Thread Safety |
|---|---|---|
| **CryptoEngine** | `encrypt_aes_gcm()`, `decrypt_aes_gcm()`, `derive_kek_argon2id()`, `wrap_key_aeskw()`, `unwrap_key_aeskw()`, `generate_nonce()` | Stateless — inherently thread-safe |
| **KeyManager** | `derive_and_unwrap_mek(password)`, `rotate_mek()`, `destroy_all_keys()`, `is_mek_loaded()` | Mutex-protected key state |
| **StorageManager** | `detect_partitions()`, `mount_volume()`, `read_blob()`, `write_blob()`, `read_metadata_index()` | File-level locking |
| **AuthManager** | `validate_password(pw)`, `get_remaining_attempts()`, `reset_attempts()`, `is_locked_out()` | Atomic attempt counter |
| **TimerEngine** | `start(seconds)`, `pause()`, `resume()`, `get_remaining()`, `serialize_state()`, `restore_state()` | Timer thread isolation |
| **ForensicLogger** | `log_event(event_type, data)`, `collect_host_fingerprint()`, `export_log()` | Append-only, write-locked |
| **ShreddingEngine** | `shred_mek()`, `shred_kek()`, `shred_key_container()`, `verify_destruction()` | Exclusive lock — blocks all |
| **TrustedDeviceManager** | `register_device()`, `check_trusted()`, `auto_unlock()`, `revoke_device()` | Read-write lock on registry |
| **GUIController** | `show_screen(name)`, `bind_signals()`, `update_countdown()`, `show_destruction_dialog()` | Qt event loop only |
| **ConfigManager** | `load()`, `get(key)`, `get_kdf_params()`, `get_timer_defaults()` | Immutable after load |

---

## 4. Key Hierarchy Diagram

The cryptographic key hierarchy is the most security-critical aspect of FORTRESS-USB. It implements a two-tier key wrapping architecture that enables crypto-shredding: destroying a single 256-bit MEK renders all encrypted data permanently irrecoverable.

```mermaid
flowchart TD
    subgraph UserInput["User Input Layer"]
        PW["User Password<br/><i>UTF-8 encoded, memory-pinned</i>"]
    end

    subgraph KDF["Key Derivation Layer"]
        SALT["Random Salt<br/><i>32 bytes, stored in key container</i>"]
        ARGON["Argon2id KDF<br/><i>m=65536 KiB, t=4 iterations<br/>p=4 parallelism, tag=32 bytes</i>"]
        KEK["Key Encryption Key — KEK<br/><i>AES-256, 32 bytes<br/>Derived from password + salt</i>"]
    end

    subgraph KeyWrapping["Key Wrapping Layer"]
        WRAP_NONCE["Wrap Nonce<br/><i>12 bytes, stored in key container</i>"]
        AES_KW["AES-256-GCM Key Wrap<br/><i>Authenticated wrapping of MEK</i>"]
        WRAP_TAG["Wrap Auth Tag<br/><i>16 bytes, stored in key container</i>"]
        WRAPPED_MEK["Wrapped MEK Blob<br/><i>48 bytes: 32-byte ciphertext + 16-byte tag<br/>Stored on Partition B</i>"]
    end

    subgraph DataEncryption["Data Encryption Layer"]
        MEK["Master Encryption Key — MEK<br/><i>AES-256, 32 bytes<br/>Random, never derived from password</i>"]
        FILE_NONCE["Per-File Nonce<br/><i>12 bytes, unique per blob</i>"]
        AES_GCM["AES-256-GCM Encryption<br/><i>Authenticated encryption of each file</i>"]
        FILE_TAG["Per-File Auth Tag<br/><i>16 bytes, stored with blob</i>"]
        ENC_DATA["Encrypted Data Blob<br/><i>Ciphertext + tag + nonce header</i>"]
    end

    subgraph MetadataEncryption["Metadata Encryption Layer"]
        META_NONCE["Metadata Nonce<br/><i>12 bytes, rotated on each write</i>"]
        META_ENC["AES-256-GCM<br/><i>Metadata encryption under MEK</i>"]
        ENC_META["Encrypted Metadata<br/><i>File index, directory tree, timestamps</i>"]
    end

    PW --> ARGON
    SALT --> ARGON
    ARGON --> KEK

    KEK --> AES_KW
    WRAP_NONCE --> AES_KW
    AES_KW --> WRAP_TAG
    AES_KW --> WRAPPED_MEK
    WRAPPED_MEK -.->|"Unwrap"| MEK

    MEK --> AES_GCM
    FILE_NONCE --> AES_GCM
    AES_GCM --> FILE_TAG
    AES_GCM --> ENC_DATA

    MEK --> META_ENC
    META_NONCE --> META_ENC
    META_ENC --> ENC_META

    style PW fill:#ff6b6b,stroke:#c0392b,color:#fff
    style KEK fill:#e67e22,stroke:#d35400,color:#fff
    style MEK fill:#e74c3c,stroke:#c0392b,color:#fff
    style ARGON fill:#3498db,stroke:#2980b9,color:#fff
    style AES_KW fill:#3498db,stroke:#2980b9,color:#fff
    style AES_GCM fill:#3498db,stroke:#2980b9,color:#fff
    style META_ENC fill:#3498db,stroke:#2980b9,color:#fff
    style WRAPPED_MEK fill:#2ecc71,stroke:#27ae60,color:#fff
    style ENC_DATA fill:#2ecc71,stroke:#27ae60,color:#fff
    style ENC_META fill:#2ecc71,stroke:#27ae60,color:#fff
    style SALT fill:#9b59b6,stroke:#8e44ad,color:#fff
    style WRAP_NONCE fill:#9b59b6,stroke:#8e44ad,color:#fff
    style FILE_NONCE fill:#9b59b6,stroke:#8e44ad,color:#fff
    style META_NONCE fill:#9b59b6,stroke:#8e44ad,color:#fff
    style WRAP_TAG fill:#f39c12,stroke:#e67e22,color:#fff
    style FILE_TAG fill:#f39c12,stroke:#e67e22,color:#fff
```

### Key Container File Structure

The key container is a binary file stored on Partition B. Its layout:

| Offset | Length | Field | Description |
|---|---|---|---|
| `0x00` | 4 | Magic | `0x464F5254` ("FORT") |
| `0x04` | 2 | Version | Key container format version (currently `0x0001`) |
| `0x06` | 2 | KDF ID | `0x0001` = Argon2id |
| `0x08` | 4 | Argon2id Memory | KiB (default: 65536) |
| `0x0C` | 4 | Argon2id Time | Iterations (default: 4) |
| `0x10` | 4 | Argon2id Parallelism | Lanes (default: 4) |
| `0x14` | 32 | Salt | Random salt for Argon2id |
| `0x34` | 12 | Wrap Nonce | Nonce used for AES-GCM key wrapping |
| `0x40` | 32 | Wrapped MEK | MEK ciphertext encrypted under KEK |
| `0x60` | 16 | Wrap Auth Tag | GCM authentication tag for wrapped MEK |
| `0x70` | 4 | Key Version | Monotonic counter, incremented on rotation |
| `0x74` | 32 | Integrity HMAC | HMAC-SHA256 over bytes `0x00–0x73` |

> **Crypto-Shredding Guarantee:** Overwriting bytes `0x40–0x6F` (the Wrapped MEK) with random data and then zeroing the in-memory MEK renders *all* encrypted data on Partition B permanently irrecoverable. No amount of computational power can reconstruct a randomly-generated 256-bit key.

---

## 5. Data Flow Diagram (DFD)

### Level 0 — Context DFD

The Level 0 DFD shows FORTRESS-USB as a single process with all external data flows.

```mermaid
flowchart LR
    User(["Authorized User"])
    Host(["Host Machine"])
    USB(["USB Drive"])
    TPM(["TPM 2.0"])

    FORTRESS["FORTRESS-USB<br/>Process 0"]

    User -->|"Password, file operations,<br/>timer commands"| FORTRESS
    FORTRESS -->|"Decrypted files, countdown status,<br/>auth result, destruction alert"| User

    Host -->|"Machine fingerprint,<br/>USB insertion events"| FORTRESS
    FORTRESS -->|"Volume mount requests,<br/>host info queries"| Host

    USB -->|"Encrypted blobs, key container,<br/>config, timer state, logs"| FORTRESS
    FORTRESS -->|"Updated encrypted blobs,<br/>updated timer state, log entries,<br/>shredded key container"| USB

    TPM -->|"Sealed key blobs,<br/>platform attestation"| FORTRESS
    FORTRESS -->|"Key seal requests,<br/>unseal requests"| TPM

    style FORTRESS fill:#3498db,stroke:#2980b9,color:#fff
```

### Level 1 — Decomposed DFD

The Level 1 DFD expands Process 0 into its constituent sub-processes, showing all internal data stores and inter-process flows.

```mermaid
flowchart TD
    User(["Authorized User"])
    Host(["Host Machine"])

    subgraph FORTRESS["FORTRESS-USB System"]

        P1["1.0<br/>Authentication"]
        P2["2.0<br/>Key Management"]
        P3["3.0<br/>File Encryption<br/>& Storage"]
        P4["4.0<br/>Timer Management"]
        P5["5.0<br/>Forensic Logging"]
        P6["6.0<br/>Crypto-Shredding"]
        P7["7.0<br/>Trusted Device<br/>Management"]
        P8["8.0<br/>GUI Presentation"]

        D1[("D1: Key Container<br/>(Partition B)")]
        D2[("D2: Encrypted Data Store<br/>(Partition B)")]
        D3[("D3: Forensic Log<br/>(Partition B)")]
        D4[("D4: Timer State<br/>(Partition B)")]
        D5[("D5: Config Store<br/>(Partition A)")]
        D6[("D6: Trusted Device<br/>Registry (Partition B)")]
    end

    User -->|"Password"| P8
    P8 -->|"Auth request"| P1
    P1 -->|"Auth result"| P8
    P8 -->|"Decrypted files,<br/>countdown"| User
    User -->|"File operations"| P8
    P8 -->|"File requests"| P3

    P1 -->|"Password + salt"| P2
    P2 -->|"KEK"| P2
    P2 <-->|"Read/Write<br/>wrapped MEK"| D1
    P2 -->|"MEK"| P3

    P3 <-->|"Read/Write<br/>encrypted blobs"| D2
    P3 -->|"Decrypted file data"| P8

    P4 <-->|"Read/Write<br/>timer state"| D4
    P4 -->|"Expiration event"| P6
    P4 -->|"Countdown value"| P8
    P4 -->|"Timer events"| P5

    P1 -->|"Auth events"| P5
    P5 -->|"Encrypted log entries"| D3
    P6 -->|"Destruction events"| P5

    P1 -->|"Max attempts breached"| P6
    P6 -->|"Destroy MEK/KEK"| P2
    P6 -->|"Overwrite key container"| D1
    P6 -->|"Destruction complete"| P8

    P5 <-->|"Read config"| D5

    Host -->|"Machine fingerprint"| P7
    P7 <-->|"Read/Write<br/>device registry"| D6
    P7 -->|"Auto-unlock MEK"| P2
    P7 -->|"Trust events"| P5

    style P1 fill:#e74c3c,stroke:#c0392b,color:#fff
    style P2 fill:#e67e22,stroke:#d35400,color:#fff
    style P3 fill:#2ecc71,stroke:#27ae60,color:#fff
    style P4 fill:#3498db,stroke:#2980b9,color:#fff
    style P5 fill:#9b59b6,stroke:#8e44ad,color:#fff
    style P6 fill:#c0392b,stroke:#922b21,color:#fff
    style P7 fill:#1abc9c,stroke:#16a085,color:#fff
    style P8 fill:#34495e,stroke:#2c3e50,color:#fff
```

**Data Store Definitions:**

| Store | Location | Encryption | Access Pattern |
|---|---|---|---|
| D1: Key Container | Partition B, `/vault/keystore.bin` | AES-KW wrapped MEK + HMAC | Read on unlock, write on rotation/shred |
| D2: Encrypted Data | Partition B, `/vault/data/` | AES-256-GCM per blob | Read/Write during unlocked session |
| D3: Forensic Log | Partition B, `/vault/forensic.log` | AES-256-GCM per entry | Append-only |
| D4: Timer State | Partition B, `/vault/timer.state` | AES-256-GCM | Read/Write on every tick |
| D5: Config Store | Partition A, `/config.yaml` | Plaintext (public) | Read-only |
| D6: Trusted Device Registry | Partition B, `/vault/trusted.db` | AES-256-GCM | Read on insertion, write on registration |

---

## 6. Sequence Diagrams

### 6a. Normal Unlock Flow

The standard authentication sequence from password entry through to decrypted data access.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant GUI as GUIController
    participant Auth as AuthManager
    participant Forensic as ForensicLogger
    participant KM as KeyManager
    participant Crypto as CryptoEngine
    participant Storage as StorageManager
    participant Timer as TimerEngine

    User->>GUI: Enter password
    GUI->>Auth: validate_password(password)
    Auth->>Auth: Check attempt counter < max_attempts
    Auth->>Storage: Read key container from Partition B
    Storage-->>Auth: Key container bytes (salt, params, wrapped MEK)
    Auth->>Crypto: derive_kek_argon2id(password, salt, params)
    Note over Crypto: Argon2id: m=64 MiB, t=4, p=4
    Crypto-->>Auth: KEK (32 bytes)
    Auth->>KM: unwrap_mek(kek, wrapped_mek, nonce, tag)
    KM->>Crypto: unwrap_key_aeskw(kek, wrapped_mek, nonce, tag)
    Crypto-->>KM: MEK (32 bytes)
    Note over KM: MEK stored in pinned, non-swappable memory
    KM-->>Auth: Success
    Auth->>Auth: Reset attempt counter to 0
    Auth->>Forensic: log_event(AUTH_SUCCESS, host_fingerprint)
    Auth-->>GUI: AuthResult.SUCCESS
    GUI->>Storage: mount_encrypted_volume(mek)
    Storage->>Crypto: decrypt_aes_gcm(metadata_blob, mek)
    Crypto-->>Storage: Decrypted file index
    Storage-->>GUI: File listing
    GUI->>Timer: start(remaining_seconds)
    Timer->>Storage: Read persisted timer state
    Storage-->>Timer: Timer state (remaining, last_tick)
    Timer-->>GUI: Countdown started
    GUI-->>User: Display unlocked file browser + countdown
```

### 6b. Failed Authentication Flow

What happens when a wrong password is entered, including the escalation path to crypto-shredding.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant GUI as GUIController
    participant Auth as AuthManager
    participant Forensic as ForensicLogger
    participant Crypto as CryptoEngine
    participant Shred as ShreddingEngine
    participant KM as KeyManager
    participant Storage as StorageManager

    User->>GUI: Enter wrong password
    GUI->>Auth: validate_password(wrong_password)
    Auth->>Auth: Check attempt counter < max_attempts
    Auth->>Storage: Read key container
    Storage-->>Auth: Key container bytes
    Auth->>Crypto: derive_kek_argon2id(wrong_password, salt, params)
    Crypto-->>Auth: Invalid KEK
    Auth->>Crypto: unwrap_key_aeskw(invalid_kek, wrapped_mek, nonce, tag)
    Crypto-->>Auth: GCM Authentication Failed (tag mismatch)
    Auth->>Auth: Increment attempt counter (e.g., 3 → 4)
    Auth->>Forensic: log_event(AUTH_FAILURE, attempt=4, host_fingerprint)
    Auth->>Auth: Check: attempts (4) >= max_attempts (5)?

    alt Attempts < Max (still have tries left)
        Auth-->>GUI: AuthResult.FAILURE (remaining_attempts=1)
        GUI-->>User: "Incorrect password. 1 attempt remaining."
    else Attempts >= Max (limit breached)
        Auth->>Forensic: log_event(MAX_ATTEMPTS_BREACHED, attempt=5)
        Auth->>Shred: initiate_crypto_shred(reason=MAX_ATTEMPTS)
        Shred->>KM: destroy_all_keys()
        KM->>KM: Zeroize MEK in memory (if loaded)
        KM->>KM: Zeroize KEK in memory
        KM-->>Shred: Memory keys destroyed
        Shred->>Storage: overwrite_key_container(random_bytes)
        Storage->>Storage: Write 256 bytes of CSPRNG output over key container
        Storage->>Storage: fsync() — force flush to physical media
        Storage-->>Shred: Key container overwritten
        Shred->>Shred: verify_destruction()
        Note over Shred: Re-read key container, confirm no valid structure
        Shred->>Forensic: log_event(CRYPTO_SHRED_COMPLETE, verification=PASS)
        Shred-->>Auth: Destruction confirmed
        Auth-->>GUI: AuthResult.DESTROYED
        GUI-->>User: "⚠ SECURITY BREACH — All data has been permanently destroyed."
    end
```

### 6c. Timer Expiration Flow

The countdown timer reaching zero triggers an irreversible crypto-shredding sequence.

```mermaid
sequenceDiagram
    autonumber
    participant Timer as TimerEngine
    participant Storage as StorageManager
    participant Forensic as ForensicLogger
    participant Shred as ShreddingEngine
    participant KM as KeyManager
    participant GUI as GUIController
    actor User

    Note over Timer: Timer thread ticking every 1 second
    loop Every tick
        Timer->>Timer: remaining -= 1
        Timer->>GUI: Signal: countdown_tick(remaining)
        GUI-->>User: Update countdown display
    end

    Timer->>Timer: remaining == 0
    Timer->>Timer: Set state = EXPIRED
    Timer->>Forensic: log_event(TIMER_EXPIRED, elapsed_total, last_host)
    Timer->>GUI: Signal: timer_expired()
    GUI-->>User: "⏱ Timer expired — initiating security protocol..."

    Timer->>Shred: initiate_crypto_shred(reason=TIMER_EXPIRED)
    Shred->>Forensic: log_event(SHRED_INITIATED, reason=TIMER_EXPIRED)
    Shred->>KM: destroy_all_keys()
    KM->>KM: Zeroize MEK (32 bytes → 0x00)
    KM->>KM: Zeroize KEK (32 bytes → 0x00)
    KM-->>Shred: Keys destroyed in memory
    Shred->>Storage: overwrite_key_container(random_bytes)
    Storage-->>Shred: Done
    Shred->>Storage: overwrite_key_container(zero_bytes)
    Note over Storage: Second pass: zeros to eliminate random pattern
    Storage-->>Shred: Done
    Shred->>Shred: verify_destruction()
    Shred->>Forensic: log_event(SHRED_VERIFIED, passes=2, result=PASS)
    Shred-->>Timer: Destruction complete
    GUI-->>User: "🔒 VAULT DESTROYED — Data is irrecoverable."
```

### 6d. USB Removal and Reinsertion Flow

Demonstrates the persistent timer mechanism that survives USB removal and host changes.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant GUI as GUIController
    participant Timer as TimerEngine
    participant Storage as StorageManager
    participant Crypto as CryptoEngine
    participant Auth as AuthManager
    participant Forensic as ForensicLogger

    Note over GUI: System is in UNLOCKED state, timer running
    User->>User: Physically removes USB drive

    GUI->>GUI: Detect USB removal (WMI event)
    GUI->>Timer: pause()
    Timer->>Timer: Record removal_timestamp = now()
    Timer->>Crypto: encrypt_aes_gcm(timer_state, session_key)
    Crypto-->>Timer: Encrypted timer state blob
    Timer->>Storage: write_timer_state(encrypted_blob)
    Note over Storage: Write completes if device still<br/>briefly accessible; otherwise<br/>last persisted state is used
    Timer->>Timer: Stop timer thread
    GUI->>GUI: Zeroize MEK from memory
    GUI->>GUI: Clear all decrypted data from memory
    GUI-->>User: Application closes / "USB Removed"

    Note over User: Time passes... USB is reinserted (same or different host)

    User->>User: Physically inserts USB drive
    Note over GUI: unlock.exe auto-launches from Partition A
    GUI->>Storage: detect_partitions()
    Storage-->>GUI: Partition A (read-only), Partition B (encrypted) found
    GUI->>Storage: read_timer_state()
    Storage-->>GUI: Encrypted timer state blob
    GUI->>Auth: Prompt for password
    User->>GUI: Enter password
    GUI->>Auth: validate_password(password)
    Auth-->>GUI: AuthResult.SUCCESS + MEK available

    GUI->>Timer: restore_state(encrypted_blob, mek)
    Timer->>Crypto: decrypt_aes_gcm(encrypted_blob, session_key)
    Crypto-->>Timer: Decrypted timer state
    Timer->>Timer: Calculate offline_duration = now() - removal_timestamp
    Timer->>Timer: remaining = persisted_remaining - offline_duration
    Note over Timer: Timer counted DOWN during offline period!

    alt remaining > 0
        Timer->>Timer: Resume countdown from adjusted value
        Timer->>Forensic: log_event(TIMER_RESUMED, offline_duration, new_remaining)
        Timer-->>GUI: Countdown resumed
        GUI-->>User: Display file browser + adjusted countdown
    else remaining <= 0 (expired while offline)
        Timer->>Forensic: log_event(TIMER_EXPIRED_OFFLINE, offline_duration)
        Timer->>Timer: Trigger expiration flow
        Note over Timer: → See Sequence 6c: Timer Expiration Flow
    end
```

### 6e. Trusted Host Auto-Unlock Flow

When the USB is inserted into a previously-registered trusted machine, authentication can be automatic.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant GUI as GUIController
    participant TDM as TrustedDeviceManager
    participant Forensic as ForensicLogger
    participant Crypto as CryptoEngine
    participant KM as KeyManager
    participant Storage as StorageManager
    participant Timer as TimerEngine

    User->>User: Inserts USB into host machine
    Note over GUI: unlock.exe auto-launches
    GUI->>TDM: check_trusted(current_host)
    TDM->>TDM: Collect machine fingerprint
    Note over TDM: Fingerprint = SHA-256 of:<br/>CPU ID + Motherboard Serial +<br/>BIOS UUID + OS Install ID +<br/>Machine SID

    TDM->>Storage: read_trusted_device_registry()
    Storage-->>TDM: Encrypted device registry blob
    TDM->>Crypto: decrypt_aes_gcm(registry_blob, registry_key)
    Crypto-->>TDM: List of trusted fingerprints + sealed MEK blobs

    TDM->>TDM: Search for matching fingerprint

    alt Fingerprint matches a trusted device
        TDM->>Forensic: log_event(TRUSTED_DEVICE_MATCH, fingerprint_hash)
        TDM->>TDM: Retrieve TPM-sealed MEK blob for this device
        TDM->>Crypto: tpm_unseal(sealed_mek_blob)
        Note over Crypto: TPM 2.0 unseal bound to<br/>platform PCR values
        Crypto-->>TDM: MEK (32 bytes)
        TDM->>KM: load_mek(mek)
        KM->>KM: Store MEK in pinned memory
        KM-->>TDM: MEK loaded
        TDM-->>GUI: AutoUnlockResult.SUCCESS
        GUI->>Storage: mount_encrypted_volume(mek)
        Storage-->>GUI: File listing
        GUI->>Timer: start_or_restore()
        Timer-->>GUI: Countdown active
        GUI-->>User: "🔓 Trusted device recognized — auto-unlocked"
    else Fingerprint does not match
        TDM->>Forensic: log_event(TRUSTED_DEVICE_MISMATCH, fingerprint_hash)
        TDM-->>GUI: AutoUnlockResult.NOT_TRUSTED
        GUI-->>User: Display standard password prompt
        Note over GUI: → Falls back to Sequence 6a: Normal Unlock Flow
    end
```

### 6f. Crypto-Shredding Flow

The detailed, step-by-step destruction sequence with multi-pass overwrite and verification.

```mermaid
sequenceDiagram
    autonumber
    participant Trigger as Trigger Source
    participant Shred as ShreddingEngine
    participant KM as KeyManager
    participant Storage as StorageManager
    participant Forensic as ForensicLogger
    participant GUI as GUIController

    Note over Trigger: Trigger can be: AuthManager (max attempts),<br/>TimerEngine (expiration), or User (manual)

    Trigger->>Shred: initiate_crypto_shred(reason, metadata)
    Shred->>Shred: Acquire exclusive destruction lock
    Shred->>Shred: Set system state = DESTROYING
    Shred->>GUI: Signal: destruction_started(reason)
    Shred->>Forensic: log_event(SHRED_INITIATED, reason, timestamp)

    rect rgb(255, 230, 230)
        Note over Shred,KM: Phase 1: Memory Key Destruction
        Shred->>KM: zeroize_mek()
        KM->>KM: overwrite MEK buffer with 0x00 (32 bytes)
        KM->>KM: overwrite MEK buffer with 0xFF (32 bytes)
        KM->>KM: overwrite MEK buffer with 0x00 (32 bytes)
        KM->>KM: Memory barrier / compiler fence
        KM-->>Shred: MEK zeroized (3-pass)

        Shred->>KM: zeroize_kek()
        KM->>KM: overwrite KEK buffer with 0x00 (32 bytes)
        KM->>KM: overwrite KEK buffer with 0xFF (32 bytes)
        KM->>KM: overwrite KEK buffer with 0x00 (32 bytes)
        KM->>KM: Memory barrier / compiler fence
        KM-->>Shred: KEK zeroized (3-pass)
    end

    rect rgb(255, 240, 220)
        Note over Shred,Storage: Phase 2: Disk Key Container Destruction
        Shred->>Storage: Read key container path
        Storage-->>Shred: /vault/keystore.bin

        loop 3 overwrite passes
            Shred->>Shred: Generate 256 bytes CSPRNG random data
            Shred->>Storage: overwrite_file(keystore_path, random_data)
            Storage->>Storage: Write + fsync()
            Storage-->>Shred: Write confirmed
        end

        Shred->>Storage: overwrite_file(keystore_path, zero_bytes)
        Storage->>Storage: Write + fsync()
        Storage-->>Shred: Final zero pass confirmed

        Shred->>Storage: delete_file(keystore_path)
        Storage-->>Shred: File deleted
    end

    rect rgb(230, 255, 230)
        Note over Shred: Phase 3: Destruction Verification
        Shred->>Storage: file_exists(keystore_path)
        Storage-->>Shred: false ✓
        Shred->>KM: read_mek_buffer()
        KM-->>Shred: All zeros ✓
        Shred->>KM: read_kek_buffer()
        KM-->>Shred: All zeros ✓
        Shred->>Shred: verification_result = PASS
    end

    Shred->>Forensic: log_event(SHRED_COMPLETE, passes=4, verification=PASS)
    Note over Forensic: This is the LAST log entry ever written
    Shred->>Shred: Set system state = DESTROYED
    Shred-->>Trigger: DestructionResult.VERIFIED
    Shred->>GUI: Signal: destruction_complete(verification=PASS)
    GUI->>GUI: Display permanent destruction screen
```

---

## 7. State Machine Diagram

The system state machine defines every valid state, every allowed transition, and every guard condition. Once the `DESTROYED` state is reached, there is no recovery path — this is by design.

```mermaid
stateDiagram-v2
    [*] --> INSERTED : USB physically inserted

    INSERTED --> DETECTING : unlock.exe auto-launches
    DETECTING --> PARTITION_ERROR : Partition A or B not found
    DETECTING --> CHECKING_TRUST : Partitions detected OK

    CHECKING_TRUST --> AUTO_UNLOCKING : Trusted device match found
    CHECKING_TRUST --> AWAITING_AUTH : Not a trusted device

    AUTO_UNLOCKING --> UNLOCKED : TPM unseal succeeds → MEK loaded
    AUTO_UNLOCKING --> AWAITING_AUTH : TPM unseal fails (PCR mismatch)

    AWAITING_AUTH --> AUTHENTICATING : User submits password

    AUTHENTICATING --> KEY_DERIVING : Attempt counter < max
    AUTHENTICATING --> DESTROYING : Attempt counter >= max

    KEY_DERIVING --> MEK_UNWRAPPING : KEK derived via Argon2id
    MEK_UNWRAPPING --> UNLOCKED : GCM tag valid → MEK decrypted
    MEK_UNWRAPPING --> AUTH_FAILED : GCM tag invalid (wrong password)

    AUTH_FAILED --> AWAITING_AUTH : Attempts remaining > 0
    AUTH_FAILED --> DESTROYING : Attempts remaining == 0

    UNLOCKED --> COUNTDOWN_ACTIVE : Timer started/resumed
    COUNTDOWN_ACTIVE --> UNLOCKED : Timer paused by user

    COUNTDOWN_ACTIVE --> DESTROYING : Timer reaches 0
    COUNTDOWN_ACTIVE --> LOCKED : User manually locks

    UNLOCKED --> LOCKED : User manually locks
    UNLOCKED --> SAVING_STATE : USB removal detected

    LOCKED --> AWAITING_AUTH : User requests re-auth
    LOCKED --> SAVING_STATE : USB removal detected

    SAVING_STATE --> REMOVED : Timer state persisted to disk

    REMOVED --> INSERTED : USB physically reinserted
    REMOVED --> [*] : USB abandoned (no further events)

    DESTROYING --> DESTROYED : Crypto-shred verified
    DESTROYED --> [*] : Terminal state — no recovery

    PARTITION_ERROR --> [*] : Fatal error — cannot proceed

    state DESTROYING {
        [*] --> ZEROIZING_MEMORY : Destroy MEK + KEK in RAM
        ZEROIZING_MEMORY --> OVERWRITING_DISK : Memory keys zeroized
        OVERWRITING_DISK --> VERIFYING : Key container overwritten (4 passes)
        VERIFYING --> [*] : Verification passed
    }

    note right of DESTROYED
        IRREVERSIBLE STATE
        No key material exists.
        Encrypted data is permanently
        irrecoverable. Only the forensic
        log survives (encrypted under
        its own separate key).
    end note

    note right of COUNTDOWN_ACTIVE
        Timer ticks every 1 second.
        State persisted every 30 seconds
        and on every pause/removal event.
    end note

    note left of SAVING_STATE
        Must complete within USB
        removal grace period (~500ms).
        Uses pre-serialized state buffer
        for speed.
    end note
```

**State Transition Summary:**

| From | To | Trigger | Guard |
|---|---|---|---|
| INSERTED | DETECTING | unlock.exe launches | — |
| DETECTING | CHECKING_TRUST | Valid partitions found | Both partitions readable |
| CHECKING_TRUST | AUTO_UNLOCKING | Trusted device match | Fingerprint in registry |
| CHECKING_TRUST | AWAITING_AUTH | No trust match | — |
| AWAITING_AUTH | AUTHENTICATING | Password submitted | — |
| AUTHENTICATING | KEY_DERIVING | — | attempts < max |
| AUTHENTICATING | DESTROYING | — | attempts >= max |
| KEY_DERIVING | MEK_UNWRAPPING | KEK ready | — |
| MEK_UNWRAPPING | UNLOCKED | Valid GCM tag | — |
| MEK_UNWRAPPING | AUTH_FAILED | Invalid GCM tag | — |
| AUTH_FAILED | AWAITING_AUTH | — | remaining > 0 |
| AUTH_FAILED | DESTROYING | — | remaining == 0 |
| UNLOCKED | COUNTDOWN_ACTIVE | Timer started | — |
| COUNTDOWN_ACTIVE | DESTROYING | remaining == 0 | — |
| ANY (Unlocked/Locked) | SAVING_STATE | USB removal event | — |
| DESTROYING | DESTROYED | Verification passes | — |

---

## 8. Deployment Diagram

The deployment diagram shows the physical and logical deployment topology across the USB drive and the host machine.

```mermaid
flowchart TB
    subgraph USBDrive["USB 3.x Flash Drive"]
        direction TB
        subgraph PartA["Partition A — FAT32, Read-Only"]
            direction TB
            autorun["autorun.inf<br/><i>Auto-launch configuration</i>"]
            unlockExe["unlock.exe<br/><i>PyInstaller single-file bundle</i><br/><i>~45 MB, code-signed</i>"]
            configYaml["config.yaml<br/><i>Timer defaults, UI settings,</i><br/><i>branding, version info</i>"]
            systemMeta["system.meta<br/><i>Partition UUIDs, format version,</i><br/><i>creation timestamp, HMAC</i>"]
            icon["icon.ico<br/><i>Custom drive icon</i>"]
            readme["README.txt<br/><i>User instructions</i>"]
        end

        subgraph PartB["Partition B — RAW/Unformatted, Hidden"]
            direction TB
            vaultHeader["vault_header.bin<br/><i>Magic bytes, version,</i><br/><i>partition integrity hash</i>"]
            keystore["keystore.bin<br/><i>Wrapped MEK, salt, KDF params,</i><br/><i>nonce, auth tag, key version</i>"]
            subgraph dataDir["data/"]
                blob1["blob_001.enc"]
                blob2["blob_002.enc"]
                blobN["blob_NNN.enc"]
            end
            metadataEnc["metadata.enc<br/><i>Encrypted file index,</i><br/><i>directory tree, timestamps</i>"]
            forensicLog["forensic.log<br/><i>Append-only, encrypted</i><br/><i>per-entry AES-256-GCM</i>"]
            timerState["timer.state<br/><i>Encrypted countdown value,</i><br/><i>last-tick timestamp</i>"]
            trustedDB["trusted.db<br/><i>Encrypted device registry</i><br/><i>with TPM-sealed MEK blobs</i>"]
        end
    end

    subgraph HostMachine["Host Machine — Windows 10/11"]
        direction TB
        subgraph Runtime["Runtime Environment"]
            pythonRT["Python 3.12 Runtime<br/><i>Embedded in PyInstaller bundle</i>"]
            pyside6["PySide6 / Qt 6<br/><i>GUI framework</i>"]
            cryptoLibs["cryptography 42.x<br/><i>OpenSSL 3.x backend</i>"]
            argon2Lib["argon2-cffi<br/><i>Argon2id implementation</i>"]
            wmiLib["wmi / pywin32<br/><i>Host fingerprinting</i>"]
            tpmLib["tpm2-pytss<br/><i>TPM 2.0 access</i>"]
        end

        subgraph OSServices["OS Services"]
            usbDriver["USB 3.x Host Controller Driver"]
            volumeMgr["Volume Manager / Disk Management"]
            tpmDriver["TPM 2.0 Device Driver"]
            wmiService["WMI Service (winmgmt)"]
        end

        subgraph Memory["In-Memory Only (Never Persisted)"]
            mekRAM["MEK — 32 bytes<br/><i>Pinned, non-pageable</i>"]
            kekRAM["KEK — 32 bytes<br/><i>Ephemeral, zeroized after use</i>"]
            sessionState["Session State<br/><i>Decrypted metadata cache</i>"]
        end
    end

    unlockExe -->|"Launches"| pythonRT
    pythonRT --> pyside6
    pythonRT --> cryptoLibs
    pythonRT --> argon2Lib
    pythonRT --> wmiLib
    pythonRT --> tpmLib

    usbDriver -->|"USB 3.x"| PartA
    usbDriver -->|"USB 3.x"| PartB
    wmiService -->|"COM"| wmiLib
    tpmDriver -->|"TSS"| tpmLib

    cryptoLibs --> mekRAM
    cryptoLibs --> kekRAM

    style PartA fill:#2ecc71,stroke:#27ae60,color:#fff
    style PartB fill:#e74c3c,stroke:#c0392b,color:#fff
    style Runtime fill:#3498db,stroke:#2980b9,color:#fff
    style Memory fill:#e67e22,stroke:#d35400,color:#fff
    style OSServices fill:#95a5a6,stroke:#7f8c8d,color:#fff
```

### PyInstaller Build Configuration

| Parameter | Value | Rationale |
|---|---|---|
| `--onefile` | Yes | Single `unlock.exe` for simplicity |
| `--noconsole` | Yes | GUI application, no terminal window |
| `--icon` | `icon.ico` | Custom drive/application icon |
| `--add-data` | Qt plugins, SSL certs | Required runtime dependencies |
| `--uac-admin` | No | Runs without elevation (user-space) |
| Code Signing | Authenticode (EV cert) | Prevents SmartScreen/AV warnings |
| Anti-Tamper | HMAC of exe hash in `system.meta` | Detects launcher modification |

---

## 9. Class Diagram

The class diagram captures all major classes, their attributes, methods, visibility modifiers, and inter-class relationships (inheritance, composition, dependency).

```mermaid
classDiagram
    direction TB

    class CryptoEngine {
        -_backend: OpenSSLBackend
        +encrypt_aes_gcm(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) EncryptedBlob
        +decrypt_aes_gcm(blob: EncryptedBlob, key: bytes, aad: bytes) bytes
        +derive_kek_argon2id(password: str, salt: bytes, params: KDFParams) bytes
        +wrap_key_aeskw(kek: bytes, mek: bytes, nonce: bytes) WrappedKeyBlob
        +unwrap_key_aeskw(kek: bytes, blob: WrappedKeyBlob) bytes
        +generate_nonce(length: int) bytes
        +generate_random_bytes(length: int) bytes
        +constant_time_compare(a: bytes, b: bytes) bool
        +compute_hmac_sha256(key: bytes, data: bytes) bytes
    }

    class KeyManager {
        -_mek: SecureBuffer
        -_kek: SecureBuffer
        -_mek_loaded: bool
        -_lock: threading.Lock
        +derive_and_unwrap_mek(password: str, key_container: KeyContainer) bool
        +load_mek(mek: bytes) void
        +get_mek() bytes
        +is_mek_loaded() bool
        +rotate_mek(new_password: str) KeyContainer
        +zeroize_mek() void
        +zeroize_kek() void
        +destroy_all_keys() void
        -_pin_memory(buffer: SecureBuffer) void
    }

    class StorageManager {
        -_partition_a_path: Path
        -_partition_b_path: Path
        -_mounted: bool
        -_file_lock: threading.Lock
        +detect_partitions() PartitionInfo
        +mount_volume() bool
        +unmount_volume() void
        +read_blob(blob_id: str) bytes
        +write_blob(blob_id: str, data: bytes) void
        +delete_blob(blob_id: str) void
        +read_key_container() KeyContainer
        +write_key_container(kc: KeyContainer) void
        +read_metadata_index() bytes
        +write_metadata_index(data: bytes) void
        +overwrite_file(path: Path, data: bytes) void
        +file_exists(path: Path) bool
    }

    class AuthManager {
        -_max_attempts: int
        -_current_attempts: int
        -_lockout_until: datetime
        -_rate_limit_ms: int
        +validate_password(password: str) AuthResult
        +get_remaining_attempts() int
        +is_locked_out() bool
        +reset_attempts() void
        -_check_rate_limit() bool
        -_increment_attempts() void
    }

    class TimerEngine {
        -_remaining_seconds: int
        -_total_seconds: int
        -_state: TimerState
        -_timer_thread: threading.Thread
        -_last_tick: datetime
        -_tick_interval: float
        -_callbacks: list
        +start(seconds: int) void
        +pause() void
        +resume() void
        +stop() void
        +get_remaining() int
        +get_state() TimerState
        +serialize_state() bytes
        +restore_state(data: bytes) void
        +on_tick(callback: Callable) void
        +on_expire(callback: Callable) void
        -_tick_loop() void
        -_emit_tick() void
    }

    class ForensicLogger {
        -_log_path: Path
        -_log_key: bytes
        -_entry_counter: int
        -_hash_chain: bytes
        +log_event(event_type: EventType, data: dict) void
        +collect_host_fingerprint() HostFingerprint
        +export_log() list
        +verify_chain_integrity() bool
        -_encrypt_entry(entry: LogEntry) bytes
        -_append_to_chain(entry_hash: bytes) void
        -_collect_cpu_id() str
        -_collect_motherboard_serial() str
        -_collect_bios_uuid() str
        -_collect_os_install_id() str
    }

    class ShreddingEngine {
        -_destruction_lock: threading.Lock
        -_is_destroyed: bool
        -_overwrite_passes: int
        +initiate_crypto_shred(reason: ShredReason) DestructionResult
        +verify_destruction() VerificationResult
        -_shred_memory_keys() void
        -_shred_key_container(passes: int) void
        -_generate_overwrite_pattern(pass_num: int) bytes
        -_verify_memory_zeroed() bool
        -_verify_file_deleted() bool
    }

    class TrustedDeviceManager {
        -_registry_path: Path
        -_registry_key: bytes
        -_devices: list
        +check_trusted(host: HostFingerprint) TrustResult
        +register_device(host: HostFingerprint, mek: bytes) void
        +auto_unlock(host: HostFingerprint) bytes
        +revoke_device(device_id: str) void
        +list_trusted_devices() list
        -_generate_fingerprint() HostFingerprint
        -_seal_mek_to_tpm(mek: bytes) bytes
        -_unseal_mek_from_tpm(sealed: bytes) bytes
    }

    class GUIController {
        -_app: QApplication
        -_main_window: QMainWindow
        -_current_screen: str
        -_screens: dict
        +show_screen(name: str) void
        +show_splash() void
        +show_unlock_screen() void
        +show_countdown_screen() void
        +show_file_browser() void
        +show_settings() void
        +show_destruction_dialog(reason: str) void
        +update_countdown(remaining: int) void
        +bind_signals() void
        -_setup_styles() void
        -_create_system_tray() void
    }

    class ConfigManager {
        -_config: dict
        -_config_path: Path
        -_schema: dict
        +load() void
        +get(key: str, default: Any) Any
        +get_kdf_params() KDFParams
        +get_timer_defaults() TimerDefaults
        +get_max_attempts() int
        +get_ui_theme() str
        +validate_schema() bool
    }

    %% Data Classes
    class EncryptedBlob {
        +ciphertext: bytes
        +nonce: bytes
        +tag: bytes
        +aad: bytes
    }

    class KeyContainer {
        +magic: bytes
        +version: int
        +kdf_id: int
        +argon2_memory: int
        +argon2_time: int
        +argon2_parallelism: int
        +salt: bytes
        +wrap_nonce: bytes
        +wrapped_mek: bytes
        +wrap_tag: bytes
        +key_version: int
        +integrity_hmac: bytes
    }

    class HostFingerprint {
        +cpu_id: str
        +motherboard_serial: str
        +bios_uuid: str
        +os_install_id: str
        +machine_sid: str
        +fingerprint_hash: str
        +compute_hash() str
    }

    %% Enumerations
    class AuthResult {
        <<enumeration>>
        SUCCESS
        FAILURE
        LOCKED_OUT
        DESTROYED
    }

    class TimerState {
        <<enumeration>>
        STOPPED
        RUNNING
        PAUSED
        EXPIRED
    }

    class ShredReason {
        <<enumeration>>
        MAX_ATTEMPTS
        TIMER_EXPIRED
        MANUAL_TRIGGER
        TAMPER_DETECTED
    }

    %% Relationships
    KeyManager *-- CryptoEngine : composition
    AuthManager --> CryptoEngine : depends
    AuthManager --> KeyManager : depends
    AuthManager --> ForensicLogger : depends
    AuthManager --> ShreddingEngine : depends
    StorageManager --> CryptoEngine : depends
    TimerEngine --> ShreddingEngine : depends
    TimerEngine --> StorageManager : depends
    TimerEngine --> ForensicLogger : depends
    ShreddingEngine --> KeyManager : depends
    ShreddingEngine --> StorageManager : depends
    ShreddingEngine --> ForensicLogger : depends
    TrustedDeviceManager --> CryptoEngine : depends
    TrustedDeviceManager --> KeyManager : depends
    TrustedDeviceManager --> ForensicLogger : depends
    ForensicLogger --> CryptoEngine : depends
    ForensicLogger --> StorageManager : depends
    GUIController --> AuthManager : depends
    GUIController --> TimerEngine : depends
    GUIController --> StorageManager : depends
    GUIController --> ConfigManager : depends
    GUIController --> TrustedDeviceManager : depends

    KeyManager --> KeyContainer : manages
    StorageManager --> EncryptedBlob : reads/writes
    TrustedDeviceManager --> HostFingerprint : uses
    AuthManager --> AuthResult : returns
    TimerEngine --> TimerState : tracks
    ShreddingEngine --> ShredReason : accepts
```

---

## 10. Physical Partition Layout Diagram

This diagram provides a byte-level view of the USB drive's physical layout, showing both partitions, their filesystem structures, and the exact on-disk format of security-critical data.

```mermaid
block-beta
    columns 1

    block:disk["USB Flash Drive — Physical Layout"]
        columns 4

        block:mbr["MBR / GPT\n(Sector 0-33)"]
            columns 1
            A["Partition Table:\nEntry 1 → Part A\nEntry 2 → Part B"]
        end

        block:parta["Partition A — FAT32, Read-Only\n~200 MB"]
            columns 1
            B["autorun.inf"]
            C["unlock.exe (~45 MB)"]
            D["config.yaml"]
            E["system.meta"]
            F["icon.ico + README.txt"]
        end

        block:partb["Partition B — RAW (No Filesystem)\nRemaining Space"]
            columns 1
            G["Vault Header (512 bytes)"]
            H["Key Container (128 bytes)"]
            I["Metadata Block (variable)"]
            J["Data Blob Region"]
            K["Forensic Log Region"]
            L["Timer State (64 bytes)"]
            M["Trusted Device Registry"]
        end

        block:spare["Reserved\nSpare Area"]
            columns 1
            N["Flash wear-leveling\nspare blocks"]
        end
    end

    style mbr fill:#95a5a6,stroke:#7f8c8d,color:#fff
    style parta fill:#2ecc71,stroke:#27ae60,color:#fff
    style partb fill:#e74c3c,stroke:#c0392b,color:#fff
    style spare fill:#bdc3c7,stroke:#95a5a6,color:#333
```

### Detailed Partition B On-Disk Layout

The following diagram shows the internal structure of Partition B at byte-level granularity. This partition uses raw block access — there is no filesystem layer, which prevents host OS indexing and casual browsing.

```mermaid
flowchart TD
    subgraph PartB["Partition B — Raw Block Layout"]
        direction TB

        subgraph VaultHeader["Vault Header — Offset 0x0000, Size 512 bytes"]
            VH1["Bytes 0x00-0x03: Magic = 0x464F5254 'FORT'"]
            VH2["Bytes 0x04-0x05: Format Version = 0x0001"]
            VH3["Bytes 0x06-0x09: Flags (encrypted, timer-enabled, etc.)"]
            VH4["Bytes 0x0A-0x11: Creation Timestamp (uint64, Unix epoch)"]
            VH5["Bytes 0x12-0x31: Partition B UUID (32 bytes)"]
            VH6["Bytes 0x32-0x51: Reserved"]
            VH7["Bytes 0x1E0-0x1FF: HMAC-SHA256 of header (integrity)"]
        end

        subgraph KeyStore["Key Container — Offset 0x0200, Size 128 bytes"]
            KS1["Bytes 0x00-0x03: Magic = 0x4B455953 'KEYS'"]
            KS2["Bytes 0x04-0x07: KDF Params (mem, time, par)"]
            KS3["Bytes 0x08-0x27: Salt (32 bytes)"]
            KS4["Bytes 0x28-0x33: Wrap Nonce (12 bytes)"]
            KS5["Bytes 0x34-0x53: Wrapped MEK (32 bytes ciphertext)"]
            KS6["Bytes 0x54-0x63: Wrap Auth Tag (16 bytes)"]
            KS7["Bytes 0x64-0x67: Key Version Counter"]
            KS8["Bytes 0x68-0x7F: HMAC-SHA256 of container"]
        end

        subgraph MetaBlock["Metadata Block — Offset 0x0280"]
            MB1["AES-256-GCM encrypted blob"]
            MB2["Contains: file index, directory tree,"]
            MB3["file sizes, timestamps, blob mappings"]
            MB4["Preceded by: 12-byte nonce + 16-byte tag"]
        end

        subgraph DataRegion["Data Blob Region — Offset 0x10000"]
            DR1["Each blob: 12B nonce | 16B tag | ciphertext"]
            DR2["Blob index in metadata maps ID → offset"]
            DR3["Free space tracked in metadata block"]
            DR4["No padding between blobs (compact)"]
        end

        subgraph LogRegion["Forensic Log Region — Last 1 MB"]
            LR1["Append-only ring buffer"]
            LR2["Each entry: sequence | timestamp | type |"]
            LR3["data | prev_hash | entry_HMAC"]
            LR4["Encrypted individually under log key"]
        end

        subgraph TimerRegion["Timer + Trust Region — Last 4 KB"]
            TR1["Timer State: remaining_sec (4B) |"]
            TR2["last_tick (8B) | total_sec (4B) |"]
            TR3["nonce (12B) | tag (16B)"]
            TR4["Trusted Device Registry: encrypted"]
            TR5["list of fingerprint-hash + sealed-MEK pairs"]
        end
    end

    VaultHeader --> KeyStore
    KeyStore --> MetaBlock
    MetaBlock --> DataRegion
    DataRegion --> LogRegion
    LogRegion --> TimerRegion

    style VaultHeader fill:#34495e,stroke:#2c3e50,color:#fff
    style KeyStore fill:#e74c3c,stroke:#c0392b,color:#fff
    style MetaBlock fill:#e67e22,stroke:#d35400,color:#fff
    style DataRegion fill:#3498db,stroke:#2980b9,color:#fff
    style LogRegion fill:#9b59b6,stroke:#8e44ad,color:#fff
    style TimerRegion fill:#1abc9c,stroke:#16a085,color:#fff
```

### Partition Comparison Table

| Property | Partition A | Partition B |
|---|---|---|
| **Filesystem** | FAT32 | Raw (no filesystem) |
| **Visibility** | Visible as removable drive | Hidden from OS |
| **Access Mode** | Read-only | Direct block I/O |
| **Size** | ~200 MB (fixed) | Remaining capacity |
| **Encryption** | None (public data only) | AES-256-GCM (all data) |
| **Purpose** | Auto-launch, configuration, branding | Secure vault for all sensitive data |
| **Survives Shred** | Yes | Encrypted data survives, keys do not |
| **OS Indexing** | Yes (FAT32 directory) | No (raw blocks, no FS metadata) |

---

## Appendix A: Diagram Legend

| Color | Meaning |
|---|---|
| 🟢 Green | Public / read-only / safe data |
| 🔴 Red | Security-critical / encrypted / sensitive |
| 🔵 Blue | Processing / computation / engine |
| 🟠 Orange | Key material / cryptographic state |
| 🟣 Purple | Logging / auditing / forensics |
| ⚪ Gray | Infrastructure / OS services |

## Appendix B: Acronyms

| Acronym | Definition |
|---|---|
| **MEK** | Master Encryption Key — the randomly-generated AES-256 key that encrypts all user data |
| **KEK** | Key Encryption Key — derived from user password via Argon2id; wraps the MEK |
| **KDF** | Key Derivation Function — Argon2id in this system |
| **GCM** | Galois/Counter Mode — authenticated encryption mode for AES |
| **AES-KW** | AES Key Wrap — NIST SP 800-38F compliant key wrapping |
| **TPM** | Trusted Platform Module — hardware security module for key sealing |
| **HMAC** | Hash-based Message Authentication Code |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator |
| **PCR** | Platform Configuration Register — TPM measurement register |
| **WMI** | Windows Management Instrumentation — hardware/OS query interface |
| **DFD** | Data Flow Diagram |
| **C4** | Context, Containers, Components, Code — architecture model by Simon Brown |

---

> **Document Control:** This architecture document is the single source of truth for FORTRESS-USB system design. All implementation must conform to these diagrams. Any deviation requires a formal Architecture Decision Record (ADR) and approval from the security lead.

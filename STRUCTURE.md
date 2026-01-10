# HepatizonCore — Project Structure & Dependencies

This document captures the intended *high-level* structure and dependency rules for the project (hexagonal architecture).

## Goals
- Keep the **Core** pure: no GUI, no platform headers, no database headers, no third-party crypto headers.
- Make crypto/storage backends **swappable** via ports (interfaces) + dependency injection.
- Keep **security primitives** always available to core (secure wipe, secure random, secure containers).

## Layers (Conceptual Targets, PascalCase)

### HepatizonInterfaces
**Role:** Public API surface: ports (interfaces) + shared types.  
**Depends on:** C++ standard library only.  
**Must not depend on:** Qt, OS headers, OpenSSL, Monocypher, SQLite.

Contains:
- Ports: `ICryptoProvider`, `IStorageRepository`, `IClock`, etc.
- Shared security types: `SecureBuffer`, `ZeroAllocator`, etc. (as types only; no OS headers).
- Shared persistence contracts that storage must understand (e.g., KDF metadata format if “smart storage”).

### HepatizonSecurity
**Role:** Always-on security primitives usable by core and adapters.  
**Depends on:** HepatizonInterfaces + OS APIs only.  
**Must not depend on:** Monocypher, OpenSSL, SQLite, Qt.

Contains:
- `SecureWipe` (OS-backed implementation in `src/security`)
- `SecureRandom` (OS CSPRNG implementation in `src/security`)
- Secure containers/helpers (`SecureBuffer`, `ScopeWipe`, `secureEquals`, etc.)

### HepatizonCore
**Role:** Pure business logic + use-cases; orchestration only.  
**Depends on:** HepatizonInterfaces + HepatizonSecurity.  
**Must not depend on:** crypto/storage backends, OS headers, Qt.

### HepatizonKdfMonocypher
**Role:** Shared KDF backend (Argon2id) used by multiple crypto providers.  
**Depends on:** HepatizonInterfaces + HepatizonSecurity + Monocypher.  
**Notes:** This is the single source of truth for the KDF implementation (Argon2id via Monocypher).

### HepatizonNative
**Role:** Native crypto provider implementation.  
**Depends on:** HepatizonInterfaces + HepatizonSecurity + (optionally) Monocypher for other primitives.  
**KDF:** Uses HepatizonKdfMonocypher (shared backend).

### HepatizonOpenSSL (Optional)
**Role:** Production crypto provider implementation.  
**Depends on:** HepatizonInterfaces + HepatizonSecurity + OpenSSL.  
**KDF:** Uses OpenSSL's Argon2id KDF; must match the persisted `KdfMetadata` contract.

### HepatizonStorageSqlite (Optional)
**Role:** SQLite/SQLCipher storage adapter implementation.  
**Depends on:** HepatizonInterfaces (+ HepatizonSecurity if needed) + SQLite/SQLCipher.

### HepatizonCli (Default) / HepatizonGui (Optional)
**Role:** Composition roots. They instantiate concrete adapters and inject ports into HepatizonCore.  
**Depends on:** HepatizonCore + selected adapters.  
**GUI additional deps:** Qt6 when enabled via `HEPC_BUILD_GUI=ON`.

## Dependency Graph (Allowed Direction)
```
HepatizonCli / HepatizonGui
        |
        v
   HepatizonCore  --->  HepatizonInterfaces
        |
        +----> (ports) ICryptoProvider / IStorageRepository / IClock ...
                    ^                    ^
                    |                    |
     HepatizonNative -------------------> HepatizonKdfMonocypher (shared KDF backend)
     HepatizonOpenSSL ------------------> OpenSSL (Argon2id KDF)
     HepatizonStorageSqlite ------------> SQLite/SQLCipher

HepatizonSecurity is usable by Core and all adapters.
```

## Smart Storage: KDF Metadata Contract
The vault stores KDF metadata as explicit fields.  
This makes the KDF metadata part of the **vault format contract**, so it must be stable and versioned.

Implications:
- `ICryptoProvider` must be able to derive the master key from the persisted metadata.
- Since multiple providers exist (Native/OpenSSL), they must agree on the same metadata structure.
- KDF policy changes require versioning/migration logic (explicit, not ad-hoc).

Bootstrap note:
- When using SQLCipher, `KdfMetadata` must be readable *before* the encrypted DB can be opened.

# HepatizonCore

HepatizonCore is my modular password manager prototype in C++20 (pet / learning project) with a CLI stub and an optional Qt 6 GUI stub.

> Status (2026-01-03): early-stage WIP. What works: security primitives, Argon2id KDF (metadata + policy), crypto providers (Native + optional OpenSSL), and a minimal storage bootstrap (SQLite vault + `vault.meta`). What’s missing: real CLI/GUI features and the final vault DB schema/migrations.

## ⚠️ Disclaimer
**This is a learning project, not a tool for daily use.**

I built Hepatizon to practice writing clean, strict C++ and to eliminate Undefined Behavior (UB) as much as possible. While I implemented the cryptography carefully, this code has not been audited.

**Do not trust this with your real passwords.** I am not responsible for any data loss. Use this repo to review the code and architecture, not to store your secrets.

---

## Key capabilities
- UI: CLI/GUI are currently stubs (GUI behind build flag).
- Security primitives: `SecureBuffer` + `ZeroAllocator`, OS-backed `secureWipe`, `ScopeWipe`, constant-time `secureEquals`, OS CSPRNG (`SecureRandom`).
- Crypto port: `ICryptoProvider` (KDF + AEAD), with a Native provider (Monocypher-backed) and an optional OpenSSL provider (`HEPC_ENABLE_OPENSSL`).
- KDF: Argon2id with versioned, persisted metadata (`KdfMetadata`) + core-owned defaults (`KdfPolicy`). Native/OpenSSL KDF parity test is best-effort (skips if the OpenSSL Argon2id KDF is unavailable at runtime).
- Storage (WIP): `IStorageRepository` + a minimal SQLite adapter storing a plaintext KDF metadata file (`vault.meta`) and an encrypted header row in `vault.db` (payload encryption is via `ICryptoProvider`).

---

## Tech stack
**Current**
- Language: C++20
- Build: CMake + vcpkg (manifest mode)
- GUI: Qt 6 (tested on 6.10.1; optional, currently a stub)
- Crypto: Monocypher (vendored), OpenSSL (optional)
- Tests: Google Test
- Data: SQLite3 (via vcpkg; used by the storage adapter)

**Planned**
- Data: SQLCipher (defense-in-depth), nlohmann/json

---

## Architecture (conceptual)
```
[ CLI / GUI ] (composition roots)
        |
        v
[ HepatizonCore ]
        |
        v
[ Ports (include/hepatizon) ]
  |-- ICryptoProvider  <--- HepatizonNative / HepatizonOpenSSL
  |-- IStorageRepository <--- storage adapters (SQLite/JSON/...)

Security primitives (secure wipe, secure random, secure containers) are always available to core and adapters.

KDF metadata is stored alongside the vault. Core defines default KDF policy/parameters, while crypto providers implement `deriveMasterKey(...)` from the persisted metadata.
```

For the target-level structure and dependency rules, see `STRUCTURE.md`.

---

## Project layout (WIP)
- `include/hepatizon/` public interfaces and shared types
- `src/` implementations (core, crypto, storage, security, ui, platform)
- `third_party/` vendored dependencies (e.g., Monocypher)
- `resources/` assets (icons), styles, translations
- `tests/` unit, integration, fixtures (GTest)
- `scripts/` helpers (e.g., windeployqt)

Example layout:
```
HepatizonCore/
├── include/
│   └── hepatizon/
│       ├── core/
│       ├── crypto/
│       ├── storage/
│       └── security/
├── third_party/
│   └── monocypher/
├── vcpkg/
├── src/
│   ├── core/
│   ├── crypto/
│   │   ├── native/
│   │   └── openssl/
│   ├── storage/
│   │   ├── sqlite/
│   │   └── json/
│   ├── security/
│   ├── ui/
│   │   ├── cli/
│   │   └── gui/
│   └── platform/
└── tests/
    ├── unit/
    └── integration/
```

## Session + security policy (current)
- Inactivity timeout is enforced inside core. UI sends activity signals and may run a timer for UX.
- Clipboard clear is handled by UI/platform code on logout/expiry.
- SecureBuffer lives in public headers; OS-specific secure wipe lives in src/security to avoid platform headers in include/.
- Monocypher is vendored in `third_party/monocypher/` and included privately by implementation `.cpp` files.
- Crypto providers implement the `ICryptoProvider` port (KDF + AEAD). OpenSSL provider is optional and gated behind `HEPC_ENABLE_OPENSSL`.

---

## Storage (current direction)
Vaults are stored as a directory containing two files:
- `vault.meta` (plaintext): versioned KDF metadata required to derive the master key (`KdfMetadata`). Salt is stored here (salt is not secret).
- `vault.db` (SQLite for now; SQLCipher later): stores encrypted application payloads as AEAD blobs (`AeadBox`).

The current SQLite adapter persists a single encrypted “vault header” row (`vault_header`, `id = 1`) containing `{nonce, tag, ciphertext}`. The header payload is intended to be a small, versioned binary struct (e.g., header version, vault id, created-at timestamp, and DB schema version) encrypted via `ICryptoProvider`.

---

## Building
Prereqs: a C++20 compiler, CMake, and (for GUI) Qt 6.10.1.
If vcpkg complains about your CMake being too old, just install the version it asks for (on Windows I hit a requirement for 3.31.10).

Note: OpenSSL is optional. Enable the OpenSSL provider with `-DHEPC_ENABLE_OPENSSL=ON` (requires OpenSSL).

Quick start (vcpkg submodule):
- Clone with submodules: `git clone --recursive https://github.com/Drewienko/HepatizonCore`
  - If already cloned: `git submodule update --init --recursive`
- Linux:
  - `./vcpkg/bootstrap-vcpkg.sh`
  - `cmake --preset linux-release-gcc`
  - `cmake --build --preset linux-release-gcc`
- Windows (PowerShell):
  - `.\vcpkg\bootstrap-vcpkg.bat`
  - `cmake --preset windows-release-msvc`
  - `cmake --build --preset windows-release-msvc --config Release`

Vcpkg is pinned via the submodule commit and `vcpkg-configuration.json`.

Presets (see `CMakePresets.json`):
- Linux GCC: `cmake --preset linux-release-gcc -DHEPC_BUILD_GUI=ON -DCMAKE_PREFIX_PATH="path/to/your/qt/6.10.1/gcc_64"`
- Linux Clang: `cmake --preset linux-release-clang -DHEPC_BUILD_GUI=ON -DCMAKE_PREFIX_PATH="path/to/your/qt/6.10.1/gcc_64"`
- Windows MSVC (Visual Studio 2022): `cmake --preset windows-release-msvc -DHEPC_BUILD_GUI=ON -DCMAKE_PREFIX_PATH="path/to/your/qt/6.10.1/msvc2022_64"`

Build:
- Linux GCC: `cmake --build --preset linux-release-gcc`
- Linux Clang: `cmake --build --preset linux-release-clang`
- Windows MSVC: `cmake --build --preset windows-release-msvc --config Release`

Run:
- CLI (stub): `out/build/<preset>/src/ui/hepatizoncore_cli`
- GUI (stub): `out/build/<preset>/src/ui/hepatizoncore_gui`

---

## Tests
Presets drive the happy path (see `CMakePresets.json`).

- Linux (GCC debug): `cmake --preset linux-debug-gcc && cmake --build --preset linux-debug-gcc && ctest --preset linux-debug-gcc`
- Linux (GCC debug + OpenSSL provider): `cmake --preset linux-debug-gcc-openssl && cmake --build --preset linux-debug-gcc-openssl && ctest --preset linux-debug-gcc-openssl`
- Linux (Clang debug): `cmake --preset linux-debug-clang && cmake --build --preset linux-debug-clang && ctest --preset linux-debug-clang`
- Windows (MSVC debug): `cmake --preset windows-debug-msvc && cmake --build --preset windows-debug-msvc --config Debug && ctest --preset windows-debug-msvc -C Debug`
- Windows (MSVC debug + OpenSSL provider): `cmake --preset windows-debug-msvc-openssl && cmake --build --preset windows-debug-msvc-openssl --config Debug && ctest --preset windows-debug-msvc-openssl -C Debug`

Options:
- OpenSSL provider + OpenSSL-gated tests: configure with `-DHEPC_ENABLE_OPENSSL=ON` (parity test is best-effort and may skip if the Argon2id KDF is not exposed by the current OpenSSL providers/build).
- Slow KDF tests: set `HEPC_RUN_SLOW_TESTS=1` before running `ctest`.

---

## Deploying Qt GUI on Windows
Use the helper to bundle Qt DLLs/plugins next to the executable:
```
pwsh scripts/windeployqt.ps1 -BuildDir out/build/windows-release-msvc -Config Release -QtRoot "C:/Qt/6.10.1/msvc2022_64"
```
This invokes `windeployqt --compiler-runtime` for the built `hepatizoncore_gui.exe`.

---

## Next steps (planned)
- Flesh out interfaces in `include/` and implementations in `src/`
- Add storage/crypto backends wiring and session/keyfile handling
- Expand tests (unit/integration) and CI matrix for Linux/Windows

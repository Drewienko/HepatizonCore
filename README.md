# HepatizonCore

HepatizonCore is a modular, security-focused password manager in C++20 with both CLI and Qt-based GUI frontends.

> Status (2026-01-01): early-stage WIP — security primitives + Argon2id KDF implemented; storage/adapters and GUI are in progress.

---

## Key capabilities
- Hybrid UI: CLI implemented; Qt GUI scaffold (build flag).
- Security primitives: `SecureBuffer` + `ZeroAllocator`, OS-backed `secureWipe`, `ScopeWipe`, constant-time `secureEquals`, OS CSPRNG (`SecureRandom`).
- KDF: Argon2id via vendored Monocypher (policy versioned, DoS-capped, aligned work area).
- Dual-engine architecture: crypto/storage adapters are scaffolded; educational engine + storage/2FA features are planned.

---

## Tech stack
- Language: C++20
- Build: CMake
- GUI: Qt 6.10.1
- Data: SQLite3 (SQLCipher), nlohmann/json
- Crypto: Monocypher (vendored; native + KDF), OpenSSL (optional adapter)
- Tests: Google Test

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

KDF is implemented once (Monocypher Argon2id) and shared by crypto providers.
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

---

## Building
Prereqs: CMake >= 3.20, a C++20 compiler, and (for GUI) Qt 6.10.1.

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
- CLI: `out/build/<preset>/src/ui/hepatizoncore_cli`
- GUI: `out/build/<preset>/src/ui/hepatizoncore_gui`

---

## Tests
- Configure with `-DHEPC_ENABLE_TESTS=ON` (already set in debug presets)
- Run: `ctest --preset linux-debug-gcc`, `ctest --preset linux-debug-clang`, or `ctest --preset windows-debug-msvc --config Debug`
- Slow KDF tests: set `HEPC_RUN_SLOW_TESTS=1` before running `ctest`

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

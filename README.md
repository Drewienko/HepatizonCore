# HepatizonCore

HepatizonCore is a modular, security-focused password manager in C++20 with both CLI and Qt-based GUI frontends.

> Status: early-stage WIP

---

## Key capabilities
- Hybrid UI: full CLI for power users/automation, Qt GUI for desktop use.
- Dual crypto engines (strategy pattern): educational (handwritten AES-256/ChaCha20/SHA-256) and production (OpenSSL/Libsodium wrappers).
- Hardware-backed 2FA: USB keyfile + disk identifier with challenge-response; database unlocks only when the key drive is present.
- Storage abstraction: SQLite (SQLCipher), remote SQL (MySQL/PostgreSQL via ODBC/SOCI), JSON/binary flat files for export/debug.
- Import/migration: CSV/JSON/XLSX import, browser password extraction (Chrome/Firefox local storage parsing).

---

## Tech stack
- Language: C++20
- Build: CMake
- GUI: Qt 6
- Data: SQLite3, SOCI/ODBC, nlohmann/json, OpenXLSX
- Tests: Google Test

---

## Architecture (conceptual)
```
[ UI LAYER ]
    |-- CLI Application (Console)
    |-- GUI Application (Qt Window)
         |
         v
[ CORE LOGIC LAYER (Controller) ]
    |-- Session Manager (Auto-logout, Clipboard clear)
    |-- Import/Export Manager
         |
         v
[ ABSTRACTION LAYER (Interfaces) ]
    |                                   |
    v                                   v
[ ICryptoProvider ]              [ IStorageRepository ]
    |-- NativeAESImpl                |-- SQLiteRepository
    |-- NativeChaChaImpl             |-- RemoteSQLRepository
    |-- OpenSSLWrapper               |-- JsonFileRepository
```

---

## Project layout (WIP)
- `src/` core, crypto, storage, security, ui (cli/gui), utils
- `include/` public interfaces
- `resources/` assets (icons), styles, translations
- `tests/` unit, integration, fixtures (GTest)
- `scripts/` helpers (e.g., windeployqt)
- `cmake/modules/` custom CMake helpers

---

## Building
Prereqs: CMake >= 3.20, a C++20 compiler, and (for GUI) Qt 6.

Presets (see `CMakePresets.json`):
- Ninja (single-config, Linux/macOS/Windows): `cmake --preset ninja-debug -DHEPC_BUILD_GUI=ON -DCMAKE_PREFIX_PATH="/opt/Qt/6.x/gcc_64"`
- MSVC (Visual Studio 2022): `cmake --preset msvc-debug -DHEPC_BUILD_GUI=ON -DCMAKE_PREFIX_PATH="C:/Qt/6.10.1/msvc2022_64"`

Build:
- Ninja: `cmake --build --preset ninja-debug`
- MSVC: `cmake --build --preset msvc-debug --config Debug`

Run:
- CLI: `out/build/<preset>/[Debug/]hepatizoncore_cli`
- GUI: `out/build/<preset>/[Debug/]hepatizoncore_gui`

---

## Tests
- Configure with `-DHEPC_ENABLE_TESTS=ON` (already set in debug presets)
- Run: `ctest --preset ninja-debug` or `ctest --preset msvc-debug --config Debug`

---

## Deploying Qt GUI on Windows
Use the helper to bundle Qt DLLs/plugins next to the executable:
```
pwsh scripts/windeployqt.ps1 -BuildDir out/build/msvc-debug -Config Debug -QtRoot "C:/Qt/6.10.1/msvc2022_64"
```
This invokes `windeployqt --compiler-runtime` for the built `hepatizoncore_gui.exe`.

---

## Next steps (planned)
- Flesh out interfaces in `include/` and implementations in `src/`
- Add storage/crypto backends wiring and session/keyfile handling
- Expand tests (unit/integration) and CI matrix for Linux/Windows

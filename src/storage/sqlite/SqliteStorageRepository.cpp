#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/storage/IStorageRepository.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(_WIN32) && defined(HEPC_STORAGE_USE_SQLCIPHER)
#include <sqlcipher/sqlite3.h>
#else
#include <sqlite3.h>
#endif

namespace hepatizon::storage::sqlite
{
namespace
{

constexpr std::string_view g_kMetaFileName{ "vault.meta" };
constexpr std::string_view g_kDbFileName{ "vault.db" };

constexpr std::array<std::uint8_t, 8> g_kMetaMagic{ 'H', 'E', 'P', 'C', 'M', 'E', 'T', 'A' };
constexpr std::uint32_t g_kMetaVersion{ 1U };

constexpr int g_kHeaderRowId{ 1 };
constexpr std::uint8_t g_kEmptyBlobByte{ 0U };

constexpr std::uint32_t g_kByteMaskU32{ 0xFFU };
constexpr std::uint32_t g_kBitsPerByte{ 8U };

[[nodiscard]] std::filesystem::path metaPathFor(const std::filesystem::path& vaultDir)
{
    return vaultDir / std::filesystem::path{ g_kMetaFileName };
}

[[nodiscard]] std::filesystem::path dbPathFor(const std::filesystem::path& vaultDir)
{
    return vaultDir / std::filesystem::path{ g_kDbFileName };
}

void requireExactSize(std::span<const std::uint8_t> s, std::size_t expected, const char* what)
{
    if (s.size() != expected)
    {
        throw std::invalid_argument(what);
    }
}

[[nodiscard]] int checkedSqliteBytes(std::size_t n, const char* what)
{
    if (n > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        throw std::invalid_argument(what);
    }
    return static_cast<int>(n);
}

[[nodiscard]] const void* nonNullPtrForSqliteBlob(const void* ptr, int bytes)
{
    if (bytes == 0)
    {
        return &g_kEmptyBlobByte;
    }
    return ptr;
}

void writeU32LE(std::ostream& out, std::uint32_t v)
{
    std::array<std::uint8_t, 4> bytes{};
    for (std::size_t i{ 0 }; i < bytes.size(); ++i)
    {
        const std::uint32_t shiftBits{ static_cast<std::uint32_t>(i) * g_kBitsPerByte };
        bytes[i] = static_cast<std::uint8_t>((v >> shiftBits) & g_kByteMaskU32);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

[[nodiscard]] std::uint32_t readU32LE(std::istream& in)
{
    std::array<std::uint8_t, 4> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in)
    {
        throw std::runtime_error("storage: failed to read u32");
    }
    std::uint32_t v{ 0U };
    for (std::size_t i{ 0 }; i < bytes.size(); ++i)
    {
        const std::uint32_t shiftBits{ static_cast<std::uint32_t>(i) * g_kBitsPerByte };
        v |= (static_cast<std::uint32_t>(bytes[i]) << shiftBits);
    }
    return v;
}

void writeMetaFile(const std::filesystem::path& path, const hepatizon::crypto::KdfMetadata& kdf)
{
    std::ofstream out{ path, std::ios::binary | std::ios::trunc };
    if (!out)
    {
        throw std::runtime_error("storage: failed to open metadata file for writing");
    }

    out.write(reinterpret_cast<const char*>(g_kMetaMagic.data()), static_cast<std::streamsize>(g_kMetaMagic.size()));
    writeU32LE(out, g_kMetaVersion);

    writeU32LE(out, kdf.policyVersion);
    writeU32LE(out, static_cast<std::uint32_t>(kdf.algorithm));
    writeU32LE(out, kdf.argon2Version);
    writeU32LE(out, kdf.derivedKeyBytes);
    writeU32LE(out, kdf.argon2id.iterations);
    writeU32LE(out, kdf.argon2id.memoryKiB);
    writeU32LE(out, kdf.argon2id.parallelism);
    out.write(reinterpret_cast<const char*>(kdf.salt.data()), static_cast<std::streamsize>(kdf.salt.size()));

    if (!out)
    {
        throw std::runtime_error("storage: failed to write metadata file");
    }
}

[[nodiscard]] hepatizon::crypto::KdfMetadata readMetaFile(const std::filesystem::path& path)
{
    std::ifstream in{ path, std::ios::binary };
    if (!in)
    {
        throw std::runtime_error("storage: failed to open metadata file for reading");
    }

    std::array<std::uint8_t, g_kMetaMagic.size()> magic{};
    in.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
    if (!in || magic != g_kMetaMagic)
    {
        throw std::runtime_error("storage: invalid metadata magic");
    }

    const std::uint32_t version{ readU32LE(in) };
    if (version != g_kMetaVersion)
    {
        throw std::runtime_error("storage: unsupported metadata version");
    }

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = readU32LE(in);
    kdf.algorithm = static_cast<hepatizon::crypto::KdfAlgorithm>(readU32LE(in));
    kdf.argon2Version = readU32LE(in);
    kdf.derivedKeyBytes = readU32LE(in);
    kdf.argon2id.iterations = readU32LE(in);
    kdf.argon2id.memoryKiB = readU32LE(in);
    kdf.argon2id.parallelism = readU32LE(in);
    in.read(reinterpret_cast<char*>(kdf.salt.data()), static_cast<std::streamsize>(kdf.salt.size()));
    if (!in)
    {
        throw std::runtime_error("storage: truncated metadata file");
    }

    return kdf;
}

struct SqliteDbDeleter final
{
    void operator()(sqlite3* db) const noexcept
    {
        if (db != nullptr)
        {
            (void)sqlite3_close_v2(db);
        }
    }
};

struct SqliteStmtDeleter final
{
    void operator()(sqlite3_stmt* stmt) const noexcept
    {
        if (stmt != nullptr)
        {
            (void)sqlite3_finalize(stmt);
        }
    }
};

using SqliteDbPtr = std::unique_ptr<sqlite3, SqliteDbDeleter>;
using SqliteStmtPtr = std::unique_ptr<sqlite3_stmt, SqliteStmtDeleter>;

[[nodiscard]] std::string sqliteErr(sqlite3* db, const char* prefix)
{
    const char* msg{ (db != nullptr) ? sqlite3_errmsg(db) : "no-db" };
    std::string out{ prefix };
    out.append(": ");
    out.append(msg);
    return out;
}

void exec(sqlite3* db, const char* sql)
{
    char* errMsg{ nullptr };
    const int rc{ sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) };
    if (rc != SQLITE_OK)
    {
        std::string msg{ sqliteErr(db, "storage: sqlite3_exec failed") };
        if (errMsg != nullptr)
        {
            msg.append(" (");
            msg.append(errMsg);
            msg.append(")");
            sqlite3_free(errMsg);
        }
        throw std::runtime_error(msg);
    }
}

[[nodiscard]] SqliteDbPtr openDb(const std::filesystem::path& path, int flags)
{
    sqlite3* raw{ nullptr };
    const std::string filename{ path.string() };
    const int rc{ sqlite3_open_v2(filename.c_str(), &raw, flags, nullptr) };
    SqliteDbPtr db{ raw };
    if (rc != SQLITE_OK || !db)
    {
        throw std::runtime_error(sqliteErr(raw, "storage: sqlite3_open_v2 failed"));
    }
    return db;
}

[[nodiscard]] SqliteStmtPtr prepare(sqlite3* db, const char* sql)
{
    sqlite3_stmt* rawStmt{ nullptr };
    const int rc{ sqlite3_prepare_v2(db, sql, -1, &rawStmt, nullptr) };
    SqliteStmtPtr stmt{ rawStmt };
    if (rc != SQLITE_OK || !stmt)
    {
        throw std::runtime_error(sqliteErr(db, "storage: sqlite3_prepare_v2 failed"));
    }
    return stmt;
}

void ensureSchema(sqlite3* db)
{
    exec(db, "CREATE TABLE IF NOT EXISTS vault_header ("
             " id INTEGER PRIMARY KEY CHECK(id = 1),"
             " nonce BLOB NOT NULL,"
             " tag BLOB NOT NULL,"
             " ciphertext BLOB NOT NULL"
             ");");

    exec(db, "CREATE TABLE IF NOT EXISTS vault_blobs ("
             " key TEXT PRIMARY KEY,"
             " nonce BLOB NOT NULL,"
             " tag BLOB NOT NULL,"
             " ciphertext BLOB NOT NULL"
             ");");
}

void bindAeadBox(sqlite3* db, sqlite3_stmt* stmt, int nonceIndex, int tagIndex, int ciphertextIndex,
                 const hepatizon::crypto::AeadBox& box)
{
    const auto nonce{ std::span<const std::uint8_t>{ box.nonce } };
    const auto tag{ std::span<const std::uint8_t>{ box.tag } };

    if (sqlite3_bind_blob(stmt, nonceIndex, nonce.data(), checkedSqliteBytes(nonce.size(), "storage: nonce too large"),
                          SQLITE_STATIC) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind nonce failed"));
    }
    if (sqlite3_bind_blob(stmt, tagIndex, tag.data(), checkedSqliteBytes(tag.size(), "storage: tag too large"),
                          SQLITE_STATIC) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind tag failed"));
    }

    const int ctBytes{ checkedSqliteBytes(box.cipherText.size(), "storage: ciphertext too large") };
    const void* ctPtr{ nonNullPtrForSqliteBlob(box.cipherText.data(), ctBytes) };
    if ((ctBytes > 0) && (ctPtr == nullptr))
    {
        throw std::runtime_error("storage: null ciphertext pointer");
    }
    if (sqlite3_bind_blob(stmt, ciphertextIndex, ctPtr, ctBytes, SQLITE_STATIC) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind ciphertext failed"));
    }
}

[[nodiscard]] hepatizon::crypto::AeadBox readAeadBoxFromRow(sqlite3_stmt* stmt, const char* what)
{
    const void* noncePtr{ sqlite3_column_blob(stmt, 0) };
    const int nonceBytes{ sqlite3_column_bytes(stmt, 0) };

    const void* tagPtr{ sqlite3_column_blob(stmt, 1) };
    const int tagBytes{ sqlite3_column_bytes(stmt, 1) };

    const void* ctPtr{ sqlite3_column_blob(stmt, 2) };
    const int ctBytes{ sqlite3_column_bytes(stmt, 2) };

    if (nonceBytes < 0 || tagBytes < 0 || ctBytes < 0)
    {
        throw std::runtime_error(what);
    }

    if (noncePtr == nullptr || tagPtr == nullptr)
    {
        throw std::runtime_error(what);
    }

    const void* nonNullCtPtr{ nonNullPtrForSqliteBlob(ctPtr, ctBytes) };
    if ((ctBytes > 0) && (nonNullCtPtr == nullptr))
    {
        throw std::runtime_error(what);
    }

    hepatizon::crypto::AeadBox out{};
    const auto nonceSpan{ std::span<const std::uint8_t>{ static_cast<const std::uint8_t*>(noncePtr),
                                                         static_cast<std::size_t>(nonceBytes) } };
    const auto tagSpan{ std::span<const std::uint8_t>{ static_cast<const std::uint8_t*>(tagPtr),
                                                       static_cast<std::size_t>(tagBytes) } };

    requireExactSize(nonceSpan, hepatizon::crypto::g_aeadNonceBytes, "storage: invalid nonce size");
    requireExactSize(tagSpan, hepatizon::crypto::g_aeadTagBytes, "storage: invalid tag size");

    std::copy(nonceSpan.begin(), nonceSpan.end(), out.nonce.begin());
    std::copy(tagSpan.begin(), tagSpan.end(), out.tag.begin());

    out.cipherText.resize(static_cast<std::size_t>(ctBytes));
    if (ctBytes > 0)
    {
        std::memcpy(out.cipherText.data(), nonNullCtPtr, static_cast<std::size_t>(ctBytes));
    }
    return out;
}

void upsertHeader(sqlite3* db, const hepatizon::crypto::AeadBox& header)
{
    const char* sql{
        "INSERT INTO vault_header(id, nonce, tag, ciphertext) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce, tag=excluded.tag, ciphertext=excluded.ciphertext;"
    };

    auto stmt{ prepare(db, sql) };
    if (sqlite3_bind_int(stmt.get(), 1, g_kHeaderRowId) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind id failed"));
    }
    bindAeadBox(db, stmt.get(), 2, 3, 4, header);

    const int stepRc{ sqlite3_step(stmt.get()) };
    if (stepRc != SQLITE_DONE)
    {
        throw std::runtime_error(sqliteErr(db, "storage: upsert header failed"));
    }
}

void upsertBlob(sqlite3* db, std::string_view key, const hepatizon::crypto::AeadBox& value)
{
    if (key.empty())
    {
        throw std::invalid_argument("storage: empty blob key");
    }

    const char* sql{
        "INSERT INTO vault_blobs(key, nonce, tag, ciphertext) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET nonce=excluded.nonce, tag=excluded.tag, ciphertext=excluded.ciphertext;"
    };

    auto stmt{ prepare(db, sql) };

    const int keyBytes{ checkedSqliteBytes(key.size(), "storage: key too large") };
    if (sqlite3_bind_text(stmt.get(), 1, key.data(), keyBytes, SQLITE_TRANSIENT) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind key failed"));
    }
    bindAeadBox(db, stmt.get(), 2, 3, 4, value);

    const int stepRc{ sqlite3_step(stmt.get()) };
    if (stepRc != SQLITE_DONE)
    {
        throw std::runtime_error(sqliteErr(db, "storage: upsert blob failed"));
    }
}

[[nodiscard]] std::optional<hepatizon::crypto::AeadBox> loadBlob(sqlite3* db, std::string_view key)
{
    if (key.empty())
    {
        throw std::invalid_argument("storage: empty blob key");
    }

    const char* sql{ "SELECT nonce, tag, ciphertext FROM vault_blobs WHERE key = ?;" };

    auto stmt{ prepare(db, sql) };

    const int keyBytes{ checkedSqliteBytes(key.size(), "storage: key too large") };
    if (sqlite3_bind_text(stmt.get(), 1, key.data(), keyBytes, SQLITE_TRANSIENT) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind key failed"));
    }

    const int stepRc{ sqlite3_step(stmt.get()) };
    if (stepRc == SQLITE_DONE)
    {
        return std::nullopt;
    }
    if (stepRc != SQLITE_ROW)
    {
        throw std::runtime_error(sqliteErr(db, "storage: select blob failed"));
    }

    return readAeadBoxFromRow(stmt.get(), "storage: invalid vault_blobs row");
}

[[nodiscard]] hepatizon::crypto::AeadBox loadHeader(sqlite3* db)
{
    const char* sql{ "SELECT nonce, tag, ciphertext FROM vault_header WHERE id = ?;" };
    auto stmt{ prepare(db, sql) };

    if (sqlite3_bind_int(stmt.get(), 1, g_kHeaderRowId) != SQLITE_OK)
    {
        throw std::runtime_error(sqliteErr(db, "storage: bind id failed"));
    }

    const int stepRc{ sqlite3_step(stmt.get()) };
    if (stepRc == SQLITE_ROW)
    {
        return readAeadBoxFromRow(stmt.get(), "storage: invalid vault_header row");
    }

    if (stepRc == SQLITE_DONE)
    {
        throw std::runtime_error("storage: missing vault_header row");
    }

    throw std::runtime_error(sqliteErr(db, "storage: select header failed"));
}

void ensureEmptyDirOrCreate(const std::filesystem::path& vaultDir)
{
    std::error_code ec{};
    if (std::filesystem::exists(vaultDir, ec))
    {
        if (!std::filesystem::is_directory(vaultDir, ec))
        {
            throw std::invalid_argument("storage: vaultDir is not a directory");
        }

        auto it{ std::filesystem::directory_iterator(vaultDir, ec) };
        if (ec)
        {
            throw std::runtime_error("storage: failed to iterate vault directory");
        }
        if (it != std::filesystem::directory_iterator{})
        {
            throw std::invalid_argument("storage: vaultDir must be empty");
        }
        return;
    }

    if (!std::filesystem::create_directories(vaultDir, ec) || ec)
    {
        throw std::runtime_error("storage: failed to create vault directory");
    }
}

class SqliteStorageRepository final : public hepatizon::storage::IStorageRepository
{
public:
    void createVault(const std::filesystem::path& vaultDir, const hepatizon::storage::VaultInfo& info) override
    {
        ensureEmptyDirOrCreate(vaultDir);

        const auto metaPath{ metaPathFor(vaultDir) };
        const auto dbPath{ dbPathFor(vaultDir) };

        writeMetaFile(metaPath, info.kdf);

        auto db{ openDb(dbPath, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) };
        ensureSchema(db.get());
        upsertHeader(db.get(), info.encryptedHeader);
    }

    [[nodiscard]] hepatizon::storage::VaultInfo loadVaultInfo(const std::filesystem::path& vaultDir) const override
    {
        const auto metaPath{ metaPathFor(vaultDir) };
        const auto dbPath{ dbPathFor(vaultDir) };

        hepatizon::storage::VaultInfo info{};
        info.kdf = readMetaFile(metaPath);

        auto db{ openDb(dbPath, SQLITE_OPEN_READONLY) };
        info.encryptedHeader = loadHeader(db.get());
        return info;
    }

    void storeEncryptedHeader(const std::filesystem::path& vaultDir,
                              const hepatizon::crypto::AeadBox& encryptedHeader) override
    {
        const auto dbPath{ dbPathFor(vaultDir) };
        auto db{ openDb(dbPath, SQLITE_OPEN_READWRITE) };
        ensureSchema(db.get());
        upsertHeader(db.get(), encryptedHeader);
    }

    void storeBlob(const std::filesystem::path& vaultDir, std::string_view key,
                   const hepatizon::crypto::AeadBox& value) override
    {
        const auto dbPath{ dbPathFor(vaultDir) };
        auto db{ openDb(dbPath, SQLITE_OPEN_READWRITE) };
        ensureSchema(db.get());
        upsertBlob(db.get(), key, value);
    }

    [[nodiscard]] std::optional<hepatizon::crypto::AeadBox> loadBlob(const std::filesystem::path& vaultDir,
                                                                     std::string_view key) const override
    {
        const auto dbPath{ dbPathFor(vaultDir) };
        auto db{ openDb(dbPath, SQLITE_OPEN_READONLY) };
        return ::hepatizon::storage::sqlite::loadBlob(db.get(), key);
    }
};

} // namespace

[[nodiscard]] std::unique_ptr<hepatizon::storage::IStorageRepository> makeSqliteStorageRepository()
{
    return std::make_unique<SqliteStorageRepository>();
}

} // namespace hepatizon::storage::sqlite

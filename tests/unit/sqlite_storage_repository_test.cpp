#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#include "hepatizon/crypto/KdfMetadata.hpp"
#include "hepatizon/storage/StorageErrors.hpp"
#include "test_utils/TestUtils.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

#if defined(HEPC_STORAGE_USE_SQLCIPHER)
#include <sqlcipher/sqlite3.h>
#else
#include <sqlite3.h>
#endif

namespace
{

constexpr std::array<std::byte, 32> g_kTestDbKey{
    std::byte{ 0x01 }, std::byte{ 0x02 }, std::byte{ 0x03 }, std::byte{ 0x04 }, std::byte{ 0x05 }, std::byte{ 0x06 },
    std::byte{ 0x07 }, std::byte{ 0x08 }, std::byte{ 0x09 }, std::byte{ 0x0A }, std::byte{ 0x0B }, std::byte{ 0x0C },
    std::byte{ 0x0D }, std::byte{ 0x0E }, std::byte{ 0x0F }, std::byte{ 0x10 }, std::byte{ 0x11 }, std::byte{ 0x12 },
    std::byte{ 0x13 }, std::byte{ 0x14 }, std::byte{ 0x15 }, std::byte{ 0x16 }, std::byte{ 0x17 }, std::byte{ 0x18 },
    std::byte{ 0x19 }, std::byte{ 0x1A }, std::byte{ 0x1B }, std::byte{ 0x1C }, std::byte{ 0x1D }, std::byte{ 0x1E },
    std::byte{ 0x1F }, std::byte{ 0x20 }
};

[[nodiscard]] std::span<const std::byte> testDbKey() noexcept
{
    return std::span<const std::byte>{ g_kTestDbKey };
}

void writeU32LE(std::ofstream& out, std::uint32_t v)
{
    constexpr std::uint32_t kByteMaskU32{ 0xFFU };
    constexpr std::uint32_t kBitsPerByte{ 8U };

    std::array<std::uint8_t, 4> bytes{};
    for (std::size_t i{}; i < bytes.size(); ++i)
    {
        const std::uint32_t shiftBits{ static_cast<std::uint32_t>(i) * kBitsPerByte };
        bytes[i] = static_cast<std::uint8_t>((v >> shiftBits) & kByteMaskU32);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

void writeValidMetaFile(const std::filesystem::path& metaPath)
{
    constexpr std::array<std::uint8_t, 8> kMagic{ 'H', 'E', 'P', 'C', 'M', 'E', 'T', 'A' };
    constexpr std::uint32_t kMetaVersion{ 1U };
    constexpr std::uint32_t kTestMemoryKiB{ 8U };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    kdf.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    kdf.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    kdf.derivedKeyBytes = static_cast<std::uint32_t>(hepatizon::crypto::g_kMasterKeyBytes);
    kdf.argon2id =
        hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = kTestMemoryKiB, .parallelism = 1U };
    kdf.salt[0] = 0x01U;

    std::ofstream out{ metaPath, std::ios::binary | std::ios::trunc };
    ASSERT_TRUE(static_cast<bool>(out));
    out.write(reinterpret_cast<const char*>(kMagic.data()), static_cast<std::streamsize>(kMagic.size()));
    writeU32LE(out, kMetaVersion);
    writeU32LE(out, kdf.policyVersion);
    writeU32LE(out, static_cast<std::uint32_t>(kdf.algorithm));
    writeU32LE(out, kdf.argon2Version);
    writeU32LE(out, kdf.derivedKeyBytes);
    writeU32LE(out, kdf.argon2id.iterations);
    writeU32LE(out, kdf.argon2id.memoryKiB);
    writeU32LE(out, kdf.argon2id.parallelism);
    out.write(reinterpret_cast<const char*>(kdf.salt.data()), static_cast<std::streamsize>(kdf.salt.size()));
    out.flush();
    ASSERT_TRUE(static_cast<bool>(out));
}

void createEmptySchemaDb(const std::filesystem::path& dbPath)
{
    sqlite3* rawDb{ nullptr };
    const int rc{ sqlite3_open(dbPath.string().c_str(), &rawDb) };
    ASSERT_EQ(rc, SQLITE_OK);
    ASSERT_NE(rawDb, nullptr);

#if defined(HEPC_STORAGE_USE_SQLCIPHER)
    ASSERT_EQ(
        sqlite3_key(rawDb, static_cast<const void*>(testDbKey().data()), static_cast<int>(testDbKey().size())),
        SQLITE_OK);
#endif

    const char* schemaSql = "CREATE TABLE IF NOT EXISTS vault_header ("
                            " id INTEGER PRIMARY KEY CHECK(id = 1),"
                            " nonce BLOB NOT NULL,"
                            " tag BLOB NOT NULL,"
                            " ciphertext BLOB NOT NULL"
                            ");"
                            "CREATE TABLE IF NOT EXISTS vault_blobs ("
                            " key TEXT PRIMARY KEY,"
                            " nonce BLOB NOT NULL,"
                            " tag BLOB NOT NULL,"
                            " ciphertext BLOB NOT NULL"
                            ");";

    char* errMsg{ nullptr };
    const int execRc{ sqlite3_exec(rawDb, schemaSql, nullptr, nullptr, &errMsg) };
    if (execRc != SQLITE_OK && errMsg != nullptr)
    {
        sqlite3_free(errMsg);
    }
    ASSERT_EQ(execRc, SQLITE_OK);

    sqlite3_close_v2(rawDb);
}

void insertHeaderRow(sqlite3* db, std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> tag,
                     std::span<const std::uint8_t> ciphertext)
{
    sqlite3_stmt* stmt{ nullptr };
    const char* sql{ "INSERT INTO vault_header(id, nonce, tag, ciphertext) VALUES (1, ?, ?, ?);" };
    ASSERT_EQ(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr), SQLITE_OK);
    ASSERT_NE(stmt, nullptr);

    ASSERT_EQ(sqlite3_bind_blob(stmt, 1, nonce.data(), static_cast<int>(nonce.size()), SQLITE_TRANSIENT), SQLITE_OK);
    ASSERT_EQ(sqlite3_bind_blob(stmt, 2, tag.data(), static_cast<int>(tag.size()), SQLITE_TRANSIENT), SQLITE_OK);

    const std::uint8_t dummyByte{ 0U };
    const void* ctPtr{ ciphertext.empty() ? static_cast<const void*>(&dummyByte) : ciphertext.data() };
    ASSERT_EQ(sqlite3_bind_blob(stmt, 3, ctPtr, static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT), SQLITE_OK);

    ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

} // namespace

TEST(SqliteStorageRepository, CreateAndLoadVaultInfoRoundtrips)
{
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_") };
    ASSERT_FALSE(dir.empty());

    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };

    constexpr std::uint32_t kIterations{ 3U };
    constexpr std::uint32_t kMemoryMiB{ 64U };
    constexpr std::uint32_t kKiBPerMiB{ 1024U };
    constexpr std::uint32_t kParallelism{ 2U };

    constexpr std::uint8_t kNonceBase{ 0x10U };
    constexpr std::uint8_t kTagBase{ 0x80U };
    constexpr std::uint8_t kCipherByte0{ 0x42U };
    constexpr std::uint8_t kCipherByte1{ 0x99U };
    constexpr std::uint8_t kCipherByte2{ 0x01U };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    kdf.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    kdf.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    kdf.derivedKeyBytes = static_cast<std::uint32_t>(hepatizon::crypto::g_kMasterKeyBytes);
    kdf.argon2id = hepatizon::crypto::Argon2idParams{ kIterations, kMemoryMiB * kKiBPerMiB, kParallelism };
    for (std::size_t i{ 0 }; i < kdf.salt.size(); ++i)
    {
        kdf.salt[i] = static_cast<std::uint8_t>(i);
    }

    hepatizon::crypto::AeadBox header{};
    for (std::size_t i{ 0 }; i < header.nonce.size(); ++i)
    {
        header.nonce[i] = static_cast<std::uint8_t>(kNonceBase + i);
    }
    for (std::size_t i{ 0 }; i < header.tag.size(); ++i)
    {
        header.tag[i] = static_cast<std::uint8_t>(kTagBase + i);
    }
    header.cipherText = { kCipherByte0, kCipherByte1, kCipherByte2 };

    hepatizon::storage::VaultInfo info{};
    info.kdf = kdf;
    info.encryptedHeader = header;

    repo->createVault(dir, info, testDbKey());
    const auto loadedKdf{ repo->loadKdfMetadata(dir) };
    const auto loadedHeader{ repo->loadEncryptedHeader(dir, testDbKey()) };

    EXPECT_EQ(loadedKdf.policyVersion, kdf.policyVersion);
    EXPECT_EQ(static_cast<std::uint32_t>(loadedKdf.algorithm), static_cast<std::uint32_t>(kdf.algorithm));
    EXPECT_EQ(loadedKdf.argon2Version, kdf.argon2Version);
    EXPECT_EQ(loadedKdf.derivedKeyBytes, kdf.derivedKeyBytes);
    EXPECT_EQ(loadedKdf.argon2id.iterations, kdf.argon2id.iterations);
    EXPECT_EQ(loadedKdf.argon2id.memoryKiB, kdf.argon2id.memoryKiB);
    EXPECT_EQ(loadedKdf.argon2id.parallelism, kdf.argon2id.parallelism);
    EXPECT_EQ(loadedKdf.salt, kdf.salt);

    EXPECT_EQ(loadedHeader.nonce, header.nonce);
    EXPECT_EQ(loadedHeader.tag, header.tag);
    EXPECT_EQ(loadedHeader.cipherText, header.cipherText);

    std::filesystem::remove_all(dir);
}

TEST(SqliteStorageRepository, CreateAndLoadAllowsEmptyCiphertext)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_empty_ct_") };
    ASSERT_FALSE(dir.empty());

    constexpr std::uint32_t kTestMemoryKiB{ 8U };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    kdf.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    kdf.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    kdf.derivedKeyBytes = static_cast<std::uint32_t>(hepatizon::crypto::g_kMasterKeyBytes);
    kdf.argon2id =
        hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = kTestMemoryKiB, .parallelism = 1U };
    kdf.salt[0] = 0x01U;

    hepatizon::crypto::AeadBox header{};
    header.cipherText.clear();

    hepatizon::storage::VaultInfo info{};
    info.kdf = kdf;
    info.encryptedHeader = header;

    repo->createVault(dir, info, testDbKey());
    const auto loadedHeader{ repo->loadEncryptedHeader(dir, testDbKey()) };
    EXPECT_TRUE(loadedHeader.cipherText.empty());
}

TEST(SqliteStorageRepository, ListAndDeleteBlobs)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_repo_") };
    ASSERT_FALSE(dir.empty());

    constexpr std::uint32_t kTestMemoryKiB{ 8U };
    constexpr std::uint8_t kTestSaltByte0{ 0x42U };
    constexpr std::uint8_t kTestSaltByte1{ 0x99U };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.argon2id =
        hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = kTestMemoryKiB, .parallelism = 1U };
    kdf.salt[0] = kTestSaltByte0;
    kdf.salt[1] = kTestSaltByte1;

    hepatizon::crypto::AeadBox box{};
    box.nonce[0] = 0x01U;
    box.tag[0] = 0x02U;
    box.cipherText = std::vector<std::uint8_t>{ 0x03U, 0x04U };

    hepatizon::storage::VaultInfo info{};
    info.kdf = kdf;
    info.encryptedHeader = box;
    repo->createVault(dir, info, testDbKey());

    repo->storeBlob(dir, "k1", box, testDbKey());
    repo->storeBlob(dir, "k2", box, testDbKey());

    const auto keys{ repo->listBlobKeys(dir, testDbKey()) };
    EXPECT_EQ(keys.size(), 2U);

    EXPECT_TRUE(repo->deleteBlob(dir, "k1", testDbKey()));
    EXPECT_FALSE(repo->deleteBlob(dir, "k1", testDbKey()));

    const auto keys2{ repo->listBlobKeys(dir, testDbKey()) };
    EXPECT_EQ(keys2.size(), 1U);
}

TEST(SqliteStorageRepository, VaultExistsChecksForMetaAndDb)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };

    const auto missingDir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_missing_") / "does_not_exist" };
    EXPECT_FALSE(repo->vaultExists(missingDir));

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_exists_") };
    ASSERT_FALSE(dir.empty());
    EXPECT_FALSE(repo->vaultExists(dir));

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    kdf.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    kdf.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    kdf.derivedKeyBytes = static_cast<std::uint32_t>(hepatizon::crypto::g_kMasterKeyBytes);

    constexpr std::uint32_t testMemoryKiB{ 8U };
    kdf.argon2id = hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = testMemoryKiB, .parallelism = 1U };
    kdf.salt[0] = 0x01U;

    hepatizon::crypto::AeadBox header{};
    header.cipherText = std::vector<std::uint8_t>{ 0x01U };

    hepatizon::storage::VaultInfo info{};
    info.kdf = kdf;
    info.encryptedHeader = header;
    repo->createVault(dir, info, testDbKey());
    EXPECT_TRUE(repo->vaultExists(dir));

    constexpr std::string_view kMetaFile{ "vault.meta" };
    constexpr std::string_view kDbFile{ "vault.db" };

    std::filesystem::remove(dir / std::filesystem::path{ kMetaFile });
    EXPECT_FALSE(repo->vaultExists(dir));

    const auto dir2{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_exists2_") };
    ASSERT_FALSE(dir2.empty());
    repo->createVault(dir2, info, testDbKey());
    EXPECT_TRUE(repo->vaultExists(dir2));
    std::filesystem::remove(dir2 / std::filesystem::path{ kDbFile });
    EXPECT_FALSE(repo->vaultExists(dir2));
}

TEST(SqliteStorageRepository, CreateVaultRejectsNonDirectoryVaultPath)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto root{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_file_") };
    ASSERT_FALSE(root.empty());

    const auto vaultPath{ root / "vault_file" };
    {
        std::ofstream out{ vaultPath };
        ASSERT_TRUE(static_cast<bool>(out));
    }

    hepatizon::storage::VaultInfo info{};
    EXPECT_THROW(repo->createVault(vaultPath, info, testDbKey()), std::invalid_argument);
}

TEST(SqliteStorageRepository, CreateVaultRejectsNonEmptyDirectory)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_nonempty_") };
    ASSERT_FALSE(dir.empty());

    {
        std::ofstream out{ dir / "some_file" };
        ASSERT_TRUE(static_cast<bool>(out));
    }

    hepatizon::storage::VaultInfo info{};
    EXPECT_THROW(repo->createVault(dir, info, testDbKey()), std::invalid_argument);
}

TEST(SqliteStorageRepository, LoadKdfMetadataThrowsVaultNotFoundWhenMetaMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_nometa_") };
    ASSERT_FALSE(dir.empty());

    EXPECT_THROW(static_cast<void>(repo->loadKdfMetadata(dir)), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, LoadEncryptedHeaderThrowsVaultNotFoundWhenDbMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_nodb_") };
    ASSERT_FALSE(dir.empty());

    writeValidMetaFile(dir / "vault.meta");

    EXPECT_THROW(static_cast<void>(repo->loadEncryptedHeader(dir, testDbKey())), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, LoadKdfMetadataRejectsBadMetaMagic)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_badmagic_") };
    ASSERT_FALSE(dir.empty());

    std::ofstream out{ dir / "vault.meta", std::ios::binary | std::ios::trunc };
    ASSERT_TRUE(static_cast<bool>(out));
    constexpr std::string_view kBadMagic{ "NOTMAGIC" };
    out.write(kBadMagic.data(), static_cast<std::streamsize>(kBadMagic.size()));
    out.flush();

    EXPECT_THROW(static_cast<void>(repo->loadKdfMetadata(dir)), std::runtime_error);
}

TEST(SqliteStorageRepository, LoadKdfMetadataRejectsUnsupportedMetaVersion)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_badver_") };
    ASSERT_FALSE(dir.empty());

    constexpr std::array<std::uint8_t, 8> kMagic{ 'H', 'E', 'P', 'C', 'M', 'E', 'T', 'A' };
    std::ofstream out{ dir / "vault.meta", std::ios::binary | std::ios::trunc };
    ASSERT_TRUE(static_cast<bool>(out));
    out.write(reinterpret_cast<const char*>(kMagic.data()), static_cast<std::streamsize>(kMagic.size()));
    writeU32LE(out, 2U);
    out.flush();

    EXPECT_THROW(static_cast<void>(repo->loadKdfMetadata(dir)), std::runtime_error);
}

TEST(SqliteStorageRepository, LoadKdfMetadataRejectsTruncatedMetaFile)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_truncmeta_") };
    ASSERT_FALSE(dir.empty());

    constexpr std::array<std::uint8_t, 8> kMagic{ 'H', 'E', 'P', 'C', 'M', 'E', 'T', 'A' };
    std::ofstream out{ dir / "vault.meta", std::ios::binary | std::ios::trunc };
    ASSERT_TRUE(static_cast<bool>(out));
    out.write(reinterpret_cast<const char*>(kMagic.data()), static_cast<std::streamsize>(kMagic.size()));
    writeU32LE(out, 1U);
    out.flush();

    EXPECT_THROW(static_cast<void>(repo->loadKdfMetadata(dir)), std::runtime_error);
}

TEST(SqliteStorageRepository, LoadEncryptedHeaderRejectsMissingHeaderRow)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_noheader_") };
    ASSERT_FALSE(dir.empty());

    writeValidMetaFile(dir / "vault.meta");
    createEmptySchemaDb(dir / "vault.db");

    EXPECT_THROW(static_cast<void>(repo->loadEncryptedHeader(dir, testDbKey())), std::runtime_error);
}

TEST(SqliteStorageRepository, LoadEncryptedHeaderRejectsInvalidNonceSizeInHeaderRow)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_badnonce_") };
    ASSERT_FALSE(dir.empty());

    writeValidMetaFile(dir / "vault.meta");
    createEmptySchemaDb(dir / "vault.db");

    sqlite3* rawDb{ nullptr };
    ASSERT_EQ(sqlite3_open((dir / "vault.db").string().c_str(), &rawDb), SQLITE_OK);
    ASSERT_NE(rawDb, nullptr);

#if defined(HEPC_STORAGE_USE_SQLCIPHER)
    ASSERT_EQ(sqlite3_key(rawDb, static_cast<const void*>(testDbKey().data()), static_cast<int>(testDbKey().size())),
              SQLITE_OK);
#endif

    std::vector<std::uint8_t> badNonce(hepatizon::crypto::g_aeadNonceBytes - 1U, 0x00U);
    std::vector<std::uint8_t> tag(hepatizon::crypto::g_aeadTagBytes, 0x01U);
    std::vector<std::uint8_t> ciphertext{};
    insertHeaderRow(rawDb, badNonce, tag, ciphertext);
    sqlite3_close_v2(rawDb);

    EXPECT_THROW(static_cast<void>(repo->loadEncryptedHeader(dir, testDbKey())), std::invalid_argument);
}

TEST(SqliteStorageRepository, StoreEncryptedHeaderThrowsVaultNotFoundWhenDbMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_storehdr_") };
    ASSERT_FALSE(dir.empty());

    hepatizon::crypto::AeadBox box{};
    EXPECT_THROW(repo->storeEncryptedHeader(dir, box, testDbKey()), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, StoreBlobThrowsVaultNotFoundWhenDbMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_storeblob_") };
    ASSERT_FALSE(dir.empty());

    hepatizon::crypto::AeadBox box{};
    EXPECT_THROW(repo->storeBlob(dir, "k", box, testDbKey()), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, DeleteBlobThrowsVaultNotFoundWhenDbMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_delblob_") };
    ASSERT_FALSE(dir.empty());

    EXPECT_THROW(static_cast<void>(repo->deleteBlob(dir, "k", testDbKey())), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, StoreKdfMetadataThrowsVaultNotFoundWhenVaultMissing)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_storekdf_") };
    ASSERT_FALSE(dir.empty());

    hepatizon::crypto::KdfMetadata kdf{};
    EXPECT_THROW(repo->storeKdfMetadata(dir, kdf), hepatizon::storage::VaultNotFound);
}

TEST(SqliteStorageRepository, BlobOperationsThrowOnEmptyKey)
{
    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_empty_keys_") };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.derivedKeyBytes = 32;
    hepatizon::storage::VaultInfo info{ kdf, {} };
    repo->createVault(dir, info, testDbKey());

    hepatizon::crypto::AeadBox val{};

    EXPECT_THROW(repo->storeBlob(dir, "", val, testDbKey()), std::invalid_argument);
    EXPECT_THROW((void)repo->loadBlob(dir, "", testDbKey()), std::invalid_argument);
    EXPECT_THROW((void)repo->deleteBlob(dir, "", testDbKey()), std::invalid_argument);
}

TEST(SqliteStorageRepository, LoadBlobHandlesCorruptedDatabaseRows)
{

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_corrupt_") };
    const auto dbPath = dir / "vault.db";

    sqlite3* rawDb{ nullptr };
    ASSERT_EQ(sqlite3_open(dbPath.string().c_str(), &rawDb), SQLITE_OK);
    ASSERT_NE(rawDb, nullptr);

#if defined(HEPC_STORAGE_USE_SQLCIPHER)
    ASSERT_EQ(sqlite3_key(rawDb, static_cast<const void*>(testDbKey().data()), static_cast<int>(testDbKey().size())),
              SQLITE_OK);
#endif

    const char* weakSchema = "CREATE TABLE vault_blobs ("
                             " key TEXT PRIMARY KEY,"
                             " nonce BLOB,"
                             " tag BLOB,"
                             " ciphertext BLOB"
                             ");";
    char* errMsg{ nullptr };
    ASSERT_EQ(sqlite3_exec(rawDb, weakSchema, nullptr, nullptr, &errMsg), SQLITE_OK);

    const char* badInsert =
        "INSERT INTO vault_blobs (key, nonce, tag, ciphertext) VALUES ('bad_row', NULL, 'tag', 'ct');";
    ASSERT_EQ(sqlite3_exec(rawDb, badInsert, nullptr, nullptr, &errMsg), SQLITE_OK);
    sqlite3_close_v2(rawDb);

    auto repo{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };

    hepatizon::crypto::KdfMetadata kdf{};
    kdf.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    kdf.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    kdf.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    kdf.derivedKeyBytes = 32;
    kdf.argon2id.memoryKiB = 8;
    kdf.salt[0] = 1;
    writeValidMetaFile(dir / "vault.meta");

    EXPECT_THROW((void)repo->loadBlob(dir, "bad_row", testDbKey()), std::runtime_error);
}

class SqliteStorageRepositoryTests : public ::testing::Test
{
protected:
    std::filesystem::path vaultDir_;
    std::unique_ptr<hepatizon::storage::IStorageRepository> repository_;

    void SetUp() override
    {
        vaultDir_ = hepatizon::test_utils::makeSecureTempDir("test_vault_");
        ASSERT_FALSE(vaultDir_.empty());

        repository_ = hepatizon::storage::sqlite::makeSqliteStorageRepository();

        hepatizon::storage::VaultInfo info;
        std::fill(info.kdf.salt.begin(), info.kdf.salt.end(), static_cast<uint8_t>(0x00));
        info.kdf.policyVersion = 1;

        repository_->createVault(vaultDir_, info, testDbKey());
    }

    void TearDown() override
    {
        std::error_code ec;
        if (std::filesystem::exists(vaultDir_))
        {
            std::filesystem::permissions(vaultDir_, std::filesystem::perms::all, std::filesystem::perm_options::replace,
                                         ec);
        }
        std::filesystem::remove_all(vaultDir_, ec);
    }

    static hepatizon::crypto::AeadBox CreateTestBox(const std::string& content)
    {
        hepatizon::crypto::AeadBox box;
        constexpr uint8_t kNonceFill = 0xAA;
        constexpr uint8_t kTagFill = 0xBB;

        std::fill(box.nonce.begin(), box.nonce.end(), kNonceFill);
        std::fill(box.tag.begin(), box.tag.end(), kTagFill);

        box.cipherText.assign(content.begin(), content.end());
        return box;
    }
};

TEST_F(SqliteStorageRepositoryTests, StoreAndLoadBlob)
{
    const std::string kKey = "unique_key_1";
    auto originalBox = CreateTestBox("secret_payload");

    repository_->storeBlob(vaultDir_, kKey, originalBox, testDbKey());

    auto loadedBox = repository_->loadBlob(vaultDir_, kKey, testDbKey());

    ASSERT_TRUE(loadedBox.has_value());
    EXPECT_EQ(loadedBox->cipherText, originalBox.cipherText);
    EXPECT_EQ(loadedBox->nonce, originalBox.nonce);
    EXPECT_EQ(loadedBox->tag, originalBox.tag);
}

TEST_F(SqliteStorageRepositoryTests, UpsertUpdatesExistingKey)
{
    const std::string kKey = "overwrite_key";
    auto boxV1 = CreateTestBox("version_1");
    auto boxV2 = CreateTestBox("version_2");

    repository_->storeBlob(vaultDir_, kKey, boxV1, testDbKey());
    repository_->storeBlob(vaultDir_, kKey, boxV2, testDbKey());

    auto result = repository_->loadBlob(vaultDir_, kKey, testDbKey());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cipherText, boxV2.cipherText);
}

TEST_F(SqliteStorageRepositoryTests, DeleteBlobRemovesRecord)
{
    const std::string kKey = "delete_me";
    repository_->storeBlob(vaultDir_, kKey, CreateTestBox("foo"), testDbKey());

    EXPECT_TRUE(repository_->loadBlob(vaultDir_, kKey, testDbKey()).has_value());

    bool wasDeleted = repository_->deleteBlob(vaultDir_, kKey, testDbKey());
    EXPECT_TRUE(wasDeleted);

    EXPECT_FALSE(repository_->loadBlob(vaultDir_, kKey, testDbKey()).has_value());
}

TEST_F(SqliteStorageRepositoryTests, ListKeysReturnsSortedKeys)
{
    repository_->storeBlob(vaultDir_, "b_key", CreateTestBox("1"), testDbKey());
    repository_->storeBlob(vaultDir_, "a_key", CreateTestBox("2"), testDbKey());
    repository_->storeBlob(vaultDir_, "c_key", CreateTestBox("3"), testDbKey());

    std::vector<std::string> keys = repository_->listBlobKeys(vaultDir_, testDbKey());

    ASSERT_EQ(keys.size(), 3);
    EXPECT_EQ(keys[0], "a_key");
    EXPECT_EQ(keys[1], "b_key");
    EXPECT_EQ(keys[2], "c_key");
}

TEST_F(SqliteStorageRepositoryTests, CreateVaultFailsOnReadOnlyFileSystem)
{
#ifdef _WIN32
    GTEST_SKIP() << "Skipping read-only filesystem test on Windows (fs::permissions is unreliable for directories).";
#else
    const std::filesystem::path readOnlyDir{ hepatizon::test_utils::makeSecureTempDir("ro_vault_") };
    ASSERT_FALSE(readOnlyDir.empty());

    // Remove write permissions
    std::filesystem::permissions(readOnlyDir, std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::replace);

    hepatizon::storage::VaultInfo info;
    std::fill(info.kdf.salt.begin(), info.kdf.salt.end(), static_cast<uint8_t>(0x00));
    info.kdf.policyVersion = 1;

    EXPECT_THROW(repository_->createVault(readOnlyDir, info, testDbKey()), std::exception);

    // Cleanup: restore permissions so we can delete the folder
    std::filesystem::permissions(readOnlyDir, std::filesystem::perms::all, std::filesystem::perm_options::replace);
    std::filesystem::remove_all(readOnlyDir);
#endif
}

#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#include "hepatizon/crypto/KdfMetadata.hpp"
#include "test_utils/TestUtils.hpp"
#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <vector>

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

    repo->createVault(dir, info);
    const auto loaded{ repo->loadVaultInfo(dir) };

    EXPECT_EQ(loaded.kdf.policyVersion, kdf.policyVersion);
    EXPECT_EQ(static_cast<std::uint32_t>(loaded.kdf.algorithm), static_cast<std::uint32_t>(kdf.algorithm));
    EXPECT_EQ(loaded.kdf.argon2Version, kdf.argon2Version);
    EXPECT_EQ(loaded.kdf.derivedKeyBytes, kdf.derivedKeyBytes);
    EXPECT_EQ(loaded.kdf.argon2id.iterations, kdf.argon2id.iterations);
    EXPECT_EQ(loaded.kdf.argon2id.memoryKiB, kdf.argon2id.memoryKiB);
    EXPECT_EQ(loaded.kdf.argon2id.parallelism, kdf.argon2id.parallelism);
    EXPECT_EQ(loaded.kdf.salt, kdf.salt);

    EXPECT_EQ(loaded.encryptedHeader.nonce, header.nonce);
    EXPECT_EQ(loaded.encryptedHeader.tag, header.tag);
    EXPECT_EQ(loaded.encryptedHeader.cipherText, header.cipherText);

    std::filesystem::remove_all(dir);
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
    repo->createVault(dir, info);

    repo->storeBlob(dir, "k1", box);
    repo->storeBlob(dir, "k2", box);

    const auto keys{ repo->listBlobKeys(dir) };
    EXPECT_EQ(keys.size(), 2U);

    EXPECT_TRUE(repo->deleteBlob(dir, "k1"));
    EXPECT_FALSE(repo->deleteBlob(dir, "k1"));

    const auto keys2{ repo->listBlobKeys(dir) };
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
    repo->createVault(dir, info);
    EXPECT_TRUE(repo->vaultExists(dir));

    constexpr std::string_view kMetaFile{ "vault.meta" };
    constexpr std::string_view kDbFile{ "vault.db" };

    std::filesystem::remove(dir / std::filesystem::path{ kMetaFile });
    EXPECT_FALSE(repo->vaultExists(dir));

    const auto dir2{ hepatizon::test_utils::makeSecureTempDir("sqlite_storage_exists2_") };
    ASSERT_FALSE(dir2.empty());
    repo->createVault(dir2, info);
    EXPECT_TRUE(repo->vaultExists(dir2));
    std::filesystem::remove(dir2 / std::filesystem::path{ kDbFile });
    EXPECT_FALSE(repo->vaultExists(dir2));
}

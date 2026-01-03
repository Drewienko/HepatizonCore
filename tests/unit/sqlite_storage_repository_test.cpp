#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#include "hepatizon/crypto/KdfMetadata.hpp"
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

namespace
{

[[nodiscard]] std::filesystem::path makeTempDir()
{
    const auto base = std::filesystem::temp_directory_path();
    const auto dir = base / std::filesystem::path{ "hepatizoncore_sqlite_storage_test" } /
                     std::filesystem::path{ std::to_string(::testing::UnitTest::GetInstance()->random_seed()) };
    return dir;
}

} // namespace

TEST(SqliteStorageRepository, CreateAndLoadVaultInfoRoundtrips)
{
    const auto dir = makeTempDir();
    std::filesystem::remove_all(dir);

    auto repo = hepatizon::storage::sqlite::makeSqliteStorageRepository();

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
    for (std::size_t i = 0; i < kdf.salt.size(); ++i)
    {
        kdf.salt[i] = static_cast<std::uint8_t>(i);
    }

    hepatizon::crypto::AeadBox header{};
    for (std::size_t i = 0; i < header.nonce.size(); ++i)
    {
        header.nonce[i] = static_cast<std::uint8_t>(kNonceBase + i);
    }
    for (std::size_t i = 0; i < header.tag.size(); ++i)
    {
        header.tag[i] = static_cast<std::uint8_t>(kTagBase + i);
    }
    header.cipherText = { kCipherByte0, kCipherByte1, kCipherByte2 };

    hepatizon::storage::VaultInfo info{};
    info.kdf = kdf;
    info.encryptedHeader = header;

    repo->createVault(dir, info);
    const auto loaded = repo->loadVaultInfo(dir);

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

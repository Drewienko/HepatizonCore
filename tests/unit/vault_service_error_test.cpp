#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/core/VaultHeader.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/StorageErrors.hpp"
#include <cstring>
#include <gtest/gtest.h>
#include <stdexcept>

namespace
{

class DummyCrypto final : public hepatizon::crypto::ICryptoProvider
{
public:
    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey([[maybe_unused]] std::span<const std::byte> password,
                    [[maybe_unused]] const hepatizon::crypto::KdfMetadata& meta) const override
    {
        return {};
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveSubkey([[maybe_unused]] std::span<const std::uint8_t> masterKey,
                 [[maybe_unused]] std::span<const std::byte> context,
                 [[maybe_unused]] std::size_t outBytes) const override
    {
        return {};
    }

    [[nodiscard]] bool randomBytes([[maybe_unused]] std::span<std::uint8_t> out) noexcept override
    {
        return false;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    aeadEncrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] std::span<const std::byte> plainText,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return {};
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] const hepatizon::crypto::AeadBox& box,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return std::nullopt;
    }
};

class ThrowingSubkeyCrypto final : public hepatizon::crypto::ICryptoProvider
{
public:
    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey([[maybe_unused]] std::span<const std::byte> password,
                    [[maybe_unused]] const hepatizon::crypto::KdfMetadata& meta) const override
    {
        hepatizon::security::SecureBuffer out{};
        out.resize(hepatizon::crypto::g_kMasterKeyBytes);
        return out;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveSubkey([[maybe_unused]] std::span<const std::uint8_t> masterKey,
                 [[maybe_unused]] std::span<const std::byte> context,
                 [[maybe_unused]] std::size_t outBytes) const override
    {
        throw std::runtime_error{ "deriveSubkey failed" };
    }

    [[nodiscard]] bool randomBytes([[maybe_unused]] std::span<std::uint8_t> out) noexcept override
    {
        return false;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    aeadEncrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] std::span<const std::byte> plainText,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return {};
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] const hepatizon::crypto::AeadBox& box,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return std::nullopt;
    }
};

class PlaintextCrypto final : public hepatizon::crypto::ICryptoProvider
{
public:
    explicit PlaintextCrypto(hepatizon::security::SecureBuffer plain) noexcept : m_plain(std::move(plain))
    {
    }

    void setThrowOnSecretsSubkey(bool enabled) noexcept
    {
        m_throwOnSecretsSubkey = enabled;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey([[maybe_unused]] std::span<const std::byte> password,
                    [[maybe_unused]] const hepatizon::crypto::KdfMetadata& meta) const override
    {
        hepatizon::security::SecureBuffer out{};
        out.resize(hepatizon::crypto::g_kMasterKeyBytes);
        return out;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveSubkey([[maybe_unused]] std::span<const std::uint8_t> masterKey, std::span<const std::byte> context,
                 std::size_t outBytes) const override
    {
        constexpr std::string_view kSecretsKeyContext{ "hepatizon.vault.secrets.aead_key.v1" };
        if (m_throwOnSecretsSubkey && context.size() == kSecretsKeyContext.size() &&
            std::memcmp(context.data(), kSecretsKeyContext.data(), kSecretsKeyContext.size()) == 0)
        {
            throw std::runtime_error{ "deriveSubkey(secrets) failed" };
        }

        hepatizon::security::SecureBuffer out{};
        out.resize(outBytes);
        return out;
    }

    [[nodiscard]] bool randomBytes([[maybe_unused]] std::span<std::uint8_t> out) noexcept override
    {
        return false;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    aeadEncrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] std::span<const std::byte> plainText,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return {};
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] const hepatizon::crypto::AeadBox& box,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return m_plain;
    }

private:
    hepatizon::security::SecureBuffer m_plain;
    bool m_throwOnSecretsSubkey{ false };
};

class RekeyCrypto final : public hepatizon::crypto::ICryptoProvider
{
public:
    void setThrowOnAeadEncrypt(bool enabled) noexcept
    {
        m_throwOnEncrypt = enabled;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey([[maybe_unused]] std::span<const std::byte> password,
                    [[maybe_unused]] const hepatizon::crypto::KdfMetadata& meta) const override
    {
        hepatizon::security::SecureBuffer out{};
        out.resize(hepatizon::crypto::g_kMasterKeyBytes);
        return out;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveSubkey([[maybe_unused]] std::span<const std::uint8_t> masterKey,
                 [[maybe_unused]] std::span<const std::byte> context, std::size_t outBytes) const override
    {
        hepatizon::security::SecureBuffer out{};
        out.resize(outBytes);
        return out;
    }

    [[nodiscard]] bool randomBytes([[maybe_unused]] std::span<std::uint8_t> out) noexcept override
    {
        return false;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    aeadEncrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] std::span<const std::byte> plainText,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        if (m_throwOnEncrypt)
        {
            throw std::runtime_error{ "aeadEncrypt failed" };
        }
        hepatizon::crypto::AeadBox out{};
        out.cipherText.resize(plainText.size());
        return out;
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] const hepatizon::crypto::AeadBox& box,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        return std::nullopt;
    }

private:
    bool m_throwOnEncrypt{ false };
};

enum class LoadMode : std::uint8_t
{
    Returns,
    ThrowsNotFound,
    ThrowsOther,
};

class LoadVaultInfoStorage final : public hepatizon::storage::IStorageRepository
{
public:
    explicit LoadVaultInfoStorage(LoadMode mode, hepatizon::storage::VaultInfo info = {})
        : m_mode(mode), m_info(std::move(info))
    {
    }

    [[nodiscard]] bool vaultExists([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        return true;
    }

    void createVault([[maybe_unused]] const std::filesystem::path& vaultDir,
                     [[maybe_unused]] const hepatizon::storage::VaultInfo& info,
                     [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::KdfMetadata
    loadKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        if (m_mode == LoadMode::ThrowsNotFound)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        if (m_mode == LoadMode::ThrowsOther)
        {
            throw std::runtime_error{ "storage failure" };
        }
        return m_info.kdf;
    }

    void storeKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir,
                          [[maybe_unused]] const hepatizon::crypto::KdfMetadata& kdf) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                              [[maybe_unused]] const hepatizon::crypto::AeadBox& encryptedHeader,
                              [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
    }

    void storeBlob([[maybe_unused]] const std::filesystem::path& vaultDir, [[maybe_unused]] std::string_view key,
                   [[maybe_unused]] const hepatizon::crypto::AeadBox& value,
                   [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::optional<hepatizon::crypto::AeadBox>
    loadBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
             [[maybe_unused]] std::string_view key,
             [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::vector<std::string>
    listBlobKeys([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] bool deleteBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
                                  [[maybe_unused]] std::string_view key,
                                  [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    loadEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                        [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        if (m_mode == LoadMode::ThrowsNotFound)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        if (m_mode == LoadMode::ThrowsOther)
        {
            throw std::runtime_error{ "storage failure" };
        }
        return m_info.encryptedHeader;
    }

    void rekeyDb([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> oldDbKey,
                 [[maybe_unused]] std::span<const std::byte> newDbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

private:
    LoadMode m_mode{ LoadMode::Returns };
    hepatizon::storage::VaultInfo m_info{};
};

class ThrowingVaultExistsStorage final : public hepatizon::storage::IStorageRepository
{
public:
    [[nodiscard]] bool vaultExists([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        throw std::runtime_error{ "vaultExists failed" };
    }

    void createVault([[maybe_unused]] const std::filesystem::path& vaultDir,
                     [[maybe_unused]] const hepatizon::storage::VaultInfo& info,
                     [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::KdfMetadata
    loadKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir,
                          [[maybe_unused]] const hepatizon::crypto::KdfMetadata& kdf) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                              [[maybe_unused]] const hepatizon::crypto::AeadBox& encryptedHeader,
                              [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeBlob([[maybe_unused]] const std::filesystem::path& vaultDir, [[maybe_unused]] std::string_view key,
                   [[maybe_unused]] const hepatizon::crypto::AeadBox& value,
                   [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::optional<hepatizon::crypto::AeadBox>
    loadBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
             [[maybe_unused]] std::string_view key,
             [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::vector<std::string>
    listBlobKeys([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] bool deleteBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
                                  [[maybe_unused]] std::string_view key,
                                  [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    loadEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                        [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void rekeyDb([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> oldDbKey,
                 [[maybe_unused]] std::span<const std::byte> newDbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }
};

enum class RekeyStoreMode : std::uint8_t
{
    Ok,
    NotFoundOnStoreKdf,
    NotFoundOnStoreHeader,
    OtherOnStoreHeader,
};

class RekeyStorage final : public hepatizon::storage::IStorageRepository
{
public:
    explicit RekeyStorage(RekeyStoreMode mode) : m_mode(mode)
    {
    }

    [[nodiscard]] const std::vector<hepatizon::crypto::KdfMetadata>& storedKdfs() const noexcept
    {
        return m_storedKdfs;
    }

    [[nodiscard]] bool vaultExists([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        return true;
    }

    void createVault([[maybe_unused]] const std::filesystem::path& vaultDir,
                     [[maybe_unused]] const hepatizon::storage::VaultInfo& info,
                     [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::KdfMetadata
    loadKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir,
                          const hepatizon::crypto::KdfMetadata& kdf) override
    {
        if (m_mode == RekeyStoreMode::NotFoundOnStoreKdf)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        m_storedKdfs.push_back(kdf);
    }

    void storeEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                              [[maybe_unused]] const hepatizon::crypto::AeadBox& encryptedHeader,
                              [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        if (m_mode == RekeyStoreMode::NotFoundOnStoreHeader)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        if (m_mode == RekeyStoreMode::OtherOnStoreHeader)
        {
            throw std::runtime_error{ "storeEncryptedHeader failed" };
        }
    }

    void storeBlob([[maybe_unused]] const std::filesystem::path& vaultDir, [[maybe_unused]] std::string_view key,
                   [[maybe_unused]] const hepatizon::crypto::AeadBox& value,
                   [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::optional<hepatizon::crypto::AeadBox>
    loadBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
             [[maybe_unused]] std::string_view key,
             [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] std::vector<std::string>
    listBlobKeys([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] bool deleteBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
                                  [[maybe_unused]] std::string_view key,
                                  [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    loadEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                        [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void rekeyDb([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> oldDbKey,
                 [[maybe_unused]] std::span<const std::byte> newDbKey) override
    {
    }

private:
    RekeyStoreMode m_mode{ RekeyStoreMode::Ok };
    std::vector<hepatizon::crypto::KdfMetadata> m_storedKdfs;
};

[[nodiscard]] hepatizon::crypto::KdfMetadata fixedKdfMetadata() noexcept
{
    hepatizon::crypto::KdfMetadata meta{};
    meta.policyVersion = hepatizon::crypto::g_kKdfPolicyVersion;
    meta.algorithm = hepatizon::crypto::KdfAlgorithm::Argon2id;
    meta.argon2Version = hepatizon::crypto::g_kArgon2VersionV13;
    meta.derivedKeyBytes = static_cast<std::uint32_t>(hepatizon::crypto::g_kMasterKeyBytes);
    meta.argon2id = hepatizon::core::defaultArgon2idParams();
    for (std::size_t i{}; i < meta.salt.size(); ++i)
    {
        meta.salt[i] = static_cast<std::uint8_t>(i);
    }
    return meta;
}

[[nodiscard]] bool kdfEquals(const hepatizon::crypto::KdfMetadata& a, const hepatizon::crypto::KdfMetadata& b) noexcept
{
    return a.policyVersion == b.policyVersion && a.algorithm == b.algorithm && a.argon2Version == b.argon2Version &&
           a.derivedKeyBytes == b.derivedKeyBytes && a.argon2id.iterations == b.argon2id.iterations &&
           a.argon2id.memoryKiB == b.argon2id.memoryKiB && a.argon2id.parallelism == b.argon2id.parallelism &&
           a.salt == b.salt;
}

} // namespace

TEST(VaultService, OpenVaultMapsVaultNotFoundToNotFound)
{
    DummyCrypto crypto{};
    LoadVaultInfoStorage storage{ LoadMode::ThrowsNotFound };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, OpenVaultMapsUnknownStorageExceptionToStorageError)
{
    DummyCrypto crypto{};
    LoadVaultInfoStorage storage{ LoadMode::ThrowsOther };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);
}

TEST(VaultService, VaultExistsReturnsFalseWhenStorageThrows)
{
    DummyCrypto crypto{};
    ThrowingVaultExistsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    EXPECT_FALSE(service.vaultExists("any"));
}

TEST(VaultService, OpenVaultMapsHeaderKeyDerivationFailureToUnsupportedKdfMetadata)
{
    ThrowingSubkeyCrypto crypto{};
    LoadVaultInfoStorage storage{ LoadMode::Returns };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::UnsupportedKdfMetadata);
}

TEST(VaultService, OpenVaultInvalidV2HeaderPayloadReturnsInvalidVaultFormat)
{
    hepatizon::security::SecureBuffer plain{};
    plain.resize(hepatizon::core::g_vaultHeaderV2Bytes);
    PlaintextCrypto crypto{ plain };
    LoadVaultInfoStorage storage{ LoadMode::Returns };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, OpenVaultInvalidV1HeaderPayloadReturnsInvalidVaultFormat)
{
    hepatizon::security::SecureBuffer plain{};
    plain.resize(hepatizon::core::g_vaultHeaderV1Bytes);
    PlaintextCrypto crypto{ plain };
    LoadVaultInfoStorage storage{ LoadMode::Returns };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, OpenVaultV1MigrationSecretsKeyDerivationFailureReturnsUnsupportedKdfMetadata)
{
    hepatizon::core::VaultHeader header{};
    header.headerVersion = hepatizon::core::g_vaultHeaderVersionV1;
    header.dbSchemaVersion = hepatizon::core::g_vaultDbSchemaVersionCurrent;
    const auto encoded{ hepatizon::core::encodeVaultHeaderV1(header) };

    hepatizon::security::SecureBuffer plain{};
    plain.resize(encoded.size());
    for (std::size_t i{}; i < encoded.size(); ++i)
    {
        plain[i] = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(encoded[i]));
    }

    PlaintextCrypto crypto{ plain };
    crypto.setThrowOnSecretsSubkey(true);
    LoadVaultInfoStorage storage{ LoadMode::Returns };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::UnsupportedKdfMetadata);
}

TEST(VaultService, OpenVaultUnknownHeaderPayloadSizeReturnsInvalidVaultFormat)
{
    hepatizon::security::SecureBuffer plain{};
    plain.resize(1U);
    plain[0] = static_cast<std::uint8_t>('B');
    PlaintextCrypto crypto{ plain };
    LoadVaultInfoStorage storage{ LoadMode::Returns };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto password{ hepatizon::security::secureStringFrom("pw") };
    const auto result{ service.openVault("any", password) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, RekeyVaultMapsEncryptFailureToCryptoError)
{
    RekeyCrypto crypto{};
    crypto.setThrowOnAeadEncrypt(true);
    RekeyStorage storage{ RekeyStoreMode::Ok };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto oldMeta{ fixedKdfMetadata() };
    hepatizon::core::VaultHeader header{};
    hepatizon::security::SecureBuffer headerKey{};
    headerKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::security::SecureBuffer secretsKey{};
    secretsKey.resize(hepatizon::core::g_vaultSecretsKeyBytes);
    hepatizon::security::SecureBuffer dbKey{};
    dbKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::core::UnlockedVault unlocked{ oldMeta, header, std::move(headerKey), std::move(secretsKey),
                                             std::move(dbKey) };

    const auto newPassword{ hepatizon::security::secureStringFrom("new") };
    const auto result{ service.rekeyVault("any", std::move(unlocked), newPassword,
                                          hepatizon::core::defaultArgon2idParams()) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::CryptoError);
}

TEST(VaultService, RekeyVaultMapsVaultNotFoundToNotFound)
{
    RekeyCrypto crypto{};
    RekeyStorage storage{ RekeyStoreMode::NotFoundOnStoreKdf };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto oldMeta{ fixedKdfMetadata() };
    hepatizon::core::VaultHeader header{};
    hepatizon::security::SecureBuffer headerKey{};
    headerKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::security::SecureBuffer secretsKey{};
    secretsKey.resize(hepatizon::core::g_vaultSecretsKeyBytes);
    hepatizon::security::SecureBuffer dbKey{};
    dbKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::core::UnlockedVault unlocked{ oldMeta, header, std::move(headerKey), std::move(secretsKey),
                                             std::move(dbKey) };

    const auto newPassword{ hepatizon::security::secureStringFrom("new") };
    const auto result{ service.rekeyVault("any", std::move(unlocked), newPassword,
                                          hepatizon::core::defaultArgon2idParams()) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, RekeyVaultRollsBackKdfMetadataOnStorageError)
{
    RekeyCrypto crypto{};
    RekeyStorage storage{ RekeyStoreMode::OtherOnStoreHeader };
    hepatizon::core::VaultService service{ crypto, storage };

    const auto oldMeta{ fixedKdfMetadata() };
    hepatizon::core::VaultHeader header{};
    hepatizon::security::SecureBuffer headerKey{};
    headerKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::security::SecureBuffer secretsKey{};
    secretsKey.resize(hepatizon::core::g_vaultSecretsKeyBytes);
    hepatizon::security::SecureBuffer dbKey{};
    dbKey.resize(hepatizon::crypto::g_aeadKeyBytes);
    hepatizon::core::UnlockedVault unlocked{ oldMeta, header, std::move(headerKey), std::move(secretsKey),
                                             std::move(dbKey) };

    const auto newPassword{ hepatizon::security::secureStringFrom("new") };
    const auto result{ service.rekeyVault("any", std::move(unlocked), newPassword,
                                          hepatizon::core::defaultArgon2idParams()) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);

    const auto& stored{ storage.storedKdfs() };
    ASSERT_GE(stored.size(), 2U);
    EXPECT_TRUE(kdfEquals(stored.back(), oldMeta));
}

enum class AeadEncryptMode : std::uint8_t
{
    Returns,
    Throws,
};

enum class AeadDecryptMode : std::uint8_t
{
    Returns,
    ReturnsNullopt,
    Throws,
};

class SecretsCrypto final : public hepatizon::crypto::ICryptoProvider
{
public:
    SecretsCrypto() = default;

    void setEncryptMode(AeadEncryptMode mode) noexcept
    {
        m_encryptMode = mode;
    }

    void setDecryptMode(AeadDecryptMode mode) noexcept
    {
        m_decryptMode = mode;
    }

    void setDecryptPlain(hepatizon::security::SecureBuffer plain) noexcept
    {
        m_decryptPlain.swap(plain);
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey([[maybe_unused]] std::span<const std::byte> password,
                    [[maybe_unused]] const hepatizon::crypto::KdfMetadata& meta) const override
    {
        return {};
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveSubkey([[maybe_unused]] std::span<const std::uint8_t> masterKey,
                 [[maybe_unused]] std::span<const std::byte> context,
                 [[maybe_unused]] std::size_t outBytes) const override
    {
        return {};
    }

    [[nodiscard]] bool randomBytes([[maybe_unused]] std::span<std::uint8_t> out) noexcept override
    {
        return false;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    aeadEncrypt([[maybe_unused]] std::span<const std::uint8_t> key, std::span<const std::byte> plainText,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        if (m_encryptMode == AeadEncryptMode::Throws)
        {
            throw std::runtime_error{ "aeadEncrypt failed" };
        }

        hepatizon::crypto::AeadBox out{};
        out.cipherText.resize(plainText.size());
        for (std::size_t i{}; i < out.cipherText.size(); ++i)
        {
            out.cipherText[i] = std::to_integer<std::uint8_t>(plainText[i]);
        }
        return out;
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt([[maybe_unused]] std::span<const std::uint8_t> key,
                [[maybe_unused]] const hepatizon::crypto::AeadBox& box,
                [[maybe_unused]] std::span<const std::byte> associatedData) override
    {
        if (m_decryptMode == AeadDecryptMode::Throws)
        {
            throw std::runtime_error{ "aeadDecrypt failed" };
        }
        if (m_decryptMode == AeadDecryptMode::ReturnsNullopt)
        {
            return std::nullopt;
        }
        return m_decryptPlain;
    }

private:
    AeadEncryptMode m_encryptMode{ AeadEncryptMode::Returns };
    AeadDecryptMode m_decryptMode{ AeadDecryptMode::Returns };
    hepatizon::security::SecureBuffer m_decryptPlain;
};

enum class StoreBlobMode : std::uint8_t
{
    Ok,
    Throws,
};

enum class LoadBlobMode : std::uint8_t
{
    ReturnsStored,
    ReturnsNullopt,
    Throws,
};

enum class ListKeysMode : std::uint8_t
{
    Ok,
    ThrowsNotFound,
    ThrowsOther,
};

enum class DeleteBlobMode : std::uint8_t
{
    ReturnsTrue,
    ReturnsFalse,
    ThrowsNotFound,
    ThrowsOther,
};

class SecretsStorage final : public hepatizon::storage::IStorageRepository
{
public:
    void setStoreBlobMode(StoreBlobMode mode) noexcept
    {
        m_storeBlobMode = mode;
    }

    void setLoadBlobMode(LoadBlobMode mode) noexcept
    {
        m_loadBlobMode = mode;
    }

    void setListKeysMode(ListKeysMode mode) noexcept
    {
        m_listKeysMode = mode;
    }

    void setDeleteBlobMode(DeleteBlobMode mode) noexcept
    {
        m_deleteBlobMode = mode;
    }

    void setStoredBox(hepatizon::crypto::AeadBox box)
    {
        m_box = std::move(box);
    }

    [[nodiscard]] bool vaultExists([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        return true;
    }

    void createVault([[maybe_unused]] const std::filesystem::path& vaultDir,
                     [[maybe_unused]] const hepatizon::storage::VaultInfo& info,
                     [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    [[nodiscard]] hepatizon::crypto::KdfMetadata
    loadKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeKdfMetadata([[maybe_unused]] const std::filesystem::path& vaultDir,
                          [[maybe_unused]] const hepatizon::crypto::KdfMetadata& kdf) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                              [[maybe_unused]] const hepatizon::crypto::AeadBox& encryptedHeader,
                              [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void storeBlob([[maybe_unused]] const std::filesystem::path& vaultDir, [[maybe_unused]] std::string_view key,
                   const hepatizon::crypto::AeadBox& value,
                   [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        if (m_storeBlobMode == StoreBlobMode::Throws)
        {
            throw std::runtime_error{ "storeBlob failed" };
        }
        m_box = value;
    }

    [[nodiscard]] std::optional<hepatizon::crypto::AeadBox>
    loadBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
             [[maybe_unused]] std::string_view key,
             [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        if (m_loadBlobMode == LoadBlobMode::Throws)
        {
            throw std::runtime_error{ "loadBlob failed" };
        }
        if (m_loadBlobMode == LoadBlobMode::ReturnsNullopt)
        {
            return std::nullopt;
        }
        return m_box;
    }

    [[nodiscard]] std::vector<std::string>
    listBlobKeys([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        if (m_listKeysMode == ListKeysMode::ThrowsNotFound)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        if (m_listKeysMode == ListKeysMode::ThrowsOther)
        {
            throw std::runtime_error{ "listBlobKeys failed" };
        }
        return { "a", "b" };
    }

    [[nodiscard]] bool deleteBlob([[maybe_unused]] const std::filesystem::path& vaultDir,
                                  [[maybe_unused]] std::string_view key,
                                  [[maybe_unused]] std::span<const std::byte> dbKey) override
    {
        if (m_deleteBlobMode == DeleteBlobMode::ThrowsNotFound)
        {
            throw hepatizon::storage::VaultNotFound{ "vault not found" };
        }
        if (m_deleteBlobMode == DeleteBlobMode::ThrowsOther)
        {
            throw std::runtime_error{ "deleteBlob failed" };
        }
        return m_deleteBlobMode == DeleteBlobMode::ReturnsTrue;
    }

    [[nodiscard]] hepatizon::crypto::AeadBox
    loadEncryptedHeader([[maybe_unused]] const std::filesystem::path& vaultDir,
                        [[maybe_unused]] std::span<const std::byte> dbKey) const override
    {
        throw std::runtime_error{ "not implemented" };
    }

    void rekeyDb([[maybe_unused]] const std::filesystem::path& vaultDir,
                 [[maybe_unused]] std::span<const std::byte> oldDbKey,
                 [[maybe_unused]] std::span<const std::byte> newDbKey) override
    {
        throw std::runtime_error{ "not implemented" };
    }

private:
    StoreBlobMode m_storeBlobMode{ StoreBlobMode::Ok };
    LoadBlobMode m_loadBlobMode{ LoadBlobMode::ReturnsStored };
    ListKeysMode m_listKeysMode{ ListKeysMode::Ok };
    DeleteBlobMode m_deleteBlobMode{ DeleteBlobMode::ReturnsTrue };
    hepatizon::crypto::AeadBox m_box{};
};

[[nodiscard]] hepatizon::core::UnlockedVault unlockedForSecretTests()
{
    const auto meta{ fixedKdfMetadata() };
    hepatizon::core::VaultHeader header{};

    hepatizon::security::SecureBuffer headerKey{};
    headerKey.resize(hepatizon::crypto::g_aeadKeyBytes);

    hepatizon::security::SecureBuffer secretsKey{};
    secretsKey.resize(hepatizon::core::g_vaultSecretsKeyBytes);

    hepatizon::security::SecureBuffer dbKey{};
    dbKey.resize(hepatizon::crypto::g_aeadKeyBytes);

    return hepatizon::core::UnlockedVault{ meta, header, std::move(headerKey), std::move(secretsKey), std::move(dbKey) };
}

TEST(VaultService, PutSecretRejectsEmptyKey)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto value{ hepatizon::security::secureStringFrom("secret") };
    const auto result{ service.putSecret("any", unlocked, "", value) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, PutSecretMapsEncryptFailureToCryptoError)
{
    SecretsCrypto crypto{};
    crypto.setEncryptMode(AeadEncryptMode::Throws);
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto value{ hepatizon::security::secureStringFrom("secret") };
    const auto result{ service.putSecret("any", unlocked, "k", value) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::CryptoError);
}

TEST(VaultService, PutSecretMapsStoreBlobFailureToStorageError)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setStoreBlobMode(StoreBlobMode::Throws);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto value{ hepatizon::security::secureStringFrom("secret") };
    const auto result{ service.putSecret("any", unlocked, "k", value) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);
}

TEST(VaultService, GetSecretRejectsEmptyKey)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, GetSecretMapsLoadBlobExceptionToStorageError)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setLoadBlobMode(LoadBlobMode::Throws);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);
}

TEST(VaultService, GetSecretReturnsNotFoundWhenBlobIsMissing)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setLoadBlobMode(LoadBlobMode::ReturnsNullopt);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, GetSecretMapsDecryptExceptionToCryptoError)
{
    SecretsCrypto crypto{};
    crypto.setDecryptMode(AeadDecryptMode::Throws);
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::CryptoError);
}

TEST(VaultService, GetSecretReturnsAuthFailedOnNulloptDecrypt)
{
    SecretsCrypto crypto{};
    crypto.setDecryptMode(AeadDecryptMode::ReturnsNullopt);
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::AuthFailed);
}

TEST(VaultService, GetSecretReturnsPlaintextOnSuccess)
{
    hepatizon::security::SecureBuffer plain{};
    constexpr std::string_view kValue{ "secret" };
    plain.resize(kValue.size());
    for (std::size_t i{}; i < kValue.size(); ++i)
    {
        plain[i] = static_cast<std::uint8_t>(kValue[i]);
    }

    SecretsCrypto crypto{};
    crypto.setDecryptMode(AeadDecryptMode::Returns);
    crypto.setDecryptPlain(std::move(plain));
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.getSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::security::SecureString>(result));
    EXPECT_EQ(hepatizon::security::asStringView(std::get<hepatizon::security::SecureString>(result)), kValue);
}

TEST(VaultService, ListSecretKeysMapsVaultNotFoundToNotFound)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setListKeysMode(ListKeysMode::ThrowsNotFound);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.listSecretKeys("any", unlocked) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, ListSecretKeysMapsUnknownExceptionToStorageError)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setListKeysMode(ListKeysMode::ThrowsOther);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.listSecretKeys("any", unlocked) };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);
}

TEST(VaultService, DeleteSecretRejectsEmptyKey)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.deleteSecret("any", unlocked, "") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::InvalidVaultFormat);
}

TEST(VaultService, DeleteSecretReturnsNotFoundWhenKeyMissing)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setDeleteBlobMode(DeleteBlobMode::ReturnsFalse);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.deleteSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, DeleteSecretMapsVaultNotFoundToNotFound)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setDeleteBlobMode(DeleteBlobMode::ThrowsNotFound);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.deleteSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, DeleteSecretMapsUnknownExceptionToStorageError)
{
    SecretsCrypto crypto{};
    SecretsStorage storage{};
    storage.setDeleteBlobMode(DeleteBlobMode::ThrowsOther);
    hepatizon::core::VaultService service{ crypto, storage };

    auto unlocked{ unlockedForSecretTests() };
    const auto result{ service.deleteSecret("any", unlocked, "k") };

    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(result));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(result), hepatizon::core::VaultError::StorageError);
}

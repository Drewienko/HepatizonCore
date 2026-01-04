#include "hepatizon/core/VaultService.hpp"

#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/core/VaultHeaderAad.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureString.hpp"
#include <chrono>
#include <cstring>

namespace hepatizon::core
{
namespace
{

[[nodiscard]] std::uint64_t unixSecondsNow() noexcept
{
    using Clock = std::chrono::system_clock;
    const auto now = Clock::now();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    const auto count = secs.count();
    if (count < 0)
    {
        return 0U;
    }
    return static_cast<std::uint64_t>(count);
}

[[nodiscard]] bool fillRandom(hepatizon::crypto::ICryptoProvider& crypto, std::span<std::uint8_t> out) noexcept
{
    return crypto.randomBytes(out);
}

} // namespace

VaultService::VaultService(hepatizon::crypto::ICryptoProvider& crypto,
                           hepatizon::storage::IStorageRepository& storage) noexcept
    : m_crypto(&crypto), m_storage(&storage)
{
}

[[nodiscard]] VaultResult<CreatedVault> VaultService::createVault(const std::filesystem::path& vaultDir,
                                                                  std::span<const std::byte> password) noexcept
{
    return createVault(vaultDir, password, hepatizon::core::defaultArgon2idParams());
}

[[nodiscard]] VaultResult<CreatedVault>
VaultService::createVault(const std::filesystem::path& vaultDir, std::span<const std::byte> password,
                          const hepatizon::crypto::Argon2idParams& params) noexcept
{
    if (m_crypto == nullptr || m_storage == nullptr)
    {
        return VaultError::CryptoError;
    }

    const auto metaOpt = hepatizon::core::makeKdfMetadata(params);
    if (!metaOpt)
    {
        return VaultError::RandomFailed;
    }
    const auto meta = *metaOpt;

    hepatizon::security::SecureBuffer masterKey{};
    try
    {
        masterKey = m_crypto->deriveMasterKey(password, meta);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }

    VaultHeaderV1 header{};
    header.headerVersion = g_vaultHeaderVersionV1;
    header.createdAtUnixSeconds = unixSecondsNow();
    header.dbSchemaVersion = g_vaultDbSchemaVersionCurrent;
    header.flags = 0U;
    if (!fillRandom(*m_crypto, std::span<std::uint8_t>{ header.vaultId }))
    {
        return VaultError::RandomFailed;
    }

    const auto plain = encodeVaultHeaderV1(header);
    const auto aad = encodeVaultHeaderAadV1(meta);
    hepatizon::crypto::AeadBox encrypted{};
    try
    {
        encrypted = m_crypto->aeadEncrypt(masterKey, std::span<const std::byte>{ plain.data(), plain.size() },
                                          std::span<const std::byte>{ aad.data(), aad.size() });
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }

    hepatizon::storage::VaultInfo info{};
    info.kdf = meta;
    info.encryptedHeader = encrypted;

    try
    {
        m_storage->createVault(vaultDir, info);
    }
    catch (...)
    {
        return VaultError::StorageError;
    }

    return CreatedVault{ meta, header };
}

[[nodiscard]] VaultResult<UnlockedVault> VaultService::unlockVault(const std::filesystem::path& vaultDir,
                                                                   std::span<const std::byte> password) noexcept
{
    if (m_crypto == nullptr || m_storage == nullptr)
    {
        return VaultError::CryptoError;
    }

    hepatizon::storage::VaultInfo info{};
    try
    {
        info = m_storage->loadVaultInfo(vaultDir);
    }
    catch (...)
    {
        return VaultError::StorageError;
    }

    hepatizon::security::SecureBuffer masterKey{};
    try
    {
        masterKey = m_crypto->deriveMasterKey(password, info.kdf);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }

    std::optional<hepatizon::security::SecureBuffer> plainOpt{};
    try
    {
        const auto aad = encodeVaultHeaderAadV1(info.kdf);
        plainOpt = m_crypto->aeadDecrypt(masterKey, info.encryptedHeader,
                                         std::span<const std::byte>{ aad.data(), aad.size() });
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }

    if (!plainOpt)
    {
        return VaultError::AuthFailed;
    }

    const auto headerOpt = decodeVaultHeaderV1(hepatizon::security::asBytes(*plainOpt));
    if (!headerOpt)
    {
        return VaultError::InvalidVaultFormat;
    }

    if (headerOpt->dbSchemaVersion > g_vaultDbSchemaVersionCurrent)
    {
        return VaultError::MigrationRequired;
    }

    auto header = *headerOpt;
    if (header.dbSchemaVersion < g_vaultDbSchemaVersionCurrent)
    {
        while (header.dbSchemaVersion < g_vaultDbSchemaVersionCurrent)
        {
            if (header.dbSchemaVersion == g_vaultDbSchemaVersionV0 &&
                g_vaultDbSchemaVersionCurrent == g_vaultDbSchemaVersionV1)
            {
                header.dbSchemaVersion = g_vaultDbSchemaVersionV1;
                continue;
            }
            return VaultError::InvalidVaultFormat;
        }

        hepatizon::crypto::AeadBox reEncrypted{};
        try
        {
            const auto updatedPlain = encodeVaultHeaderV1(header);
            const auto aad = encodeVaultHeaderAadV1(info.kdf);
            reEncrypted =
                m_crypto->aeadEncrypt(masterKey, std::span<const std::byte>{ updatedPlain.data(), updatedPlain.size() },
                                      std::span<const std::byte>{ aad.data(), aad.size() });
        }
        catch (...)
        {
            return VaultError::CryptoError;
        }

        try
        {
            m_storage->storeEncryptedHeader(vaultDir, reEncrypted);
        }
        catch (...)
        {
            return VaultError::StorageError;
        }
    }

    return UnlockedVault{ info.kdf, header, std::move(masterKey) };
}

[[nodiscard]] VaultResult<std::monostate>
VaultService::putSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key,
                        const hepatizon::security::SecureString& value) noexcept
{
    if (m_crypto == nullptr || m_storage == nullptr)
    {
        return VaultError::CryptoError;
    }
    if (key.empty())
    {
        return VaultError::InvalidVaultFormat;
    }

    const auto keyChars = std::span<const char>{ key.data(), key.size() };
    const auto aad = std::as_bytes(keyChars);

    hepatizon::crypto::AeadBox encrypted{};
    try
    {
        encrypted = m_crypto->aeadEncrypt(v.masterKey(), hepatizon::security::asBytes(value), aad);
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }

    try
    {
        m_storage->storeBlob(vaultDir, key, encrypted);
    }
    catch (...)
    {
        return VaultError::StorageError;
    }

    return std::monostate{};
}

[[nodiscard]] VaultResult<hepatizon::security::SecureString>
VaultService::getSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key) noexcept
{
    if (m_crypto == nullptr || m_storage == nullptr)
    {
        return VaultError::CryptoError;
    }
    if (key.empty())
    {
        return VaultError::InvalidVaultFormat;
    }

    std::optional<hepatizon::crypto::AeadBox> boxOpt{};
    try
    {
        boxOpt = m_storage->loadBlob(vaultDir, key);
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
    if (!boxOpt)
    {
        return VaultError::NotFound;
    }

    const auto keyChars = std::span<const char>{ key.data(), key.size() };
    const auto aad = std::as_bytes(keyChars);

    std::optional<hepatizon::security::SecureBuffer> plainOpt{};
    try
    {
        plainOpt = m_crypto->aeadDecrypt(v.masterKey(), *boxOpt, aad);
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }
    if (!plainOpt)
    {
        return VaultError::AuthFailed;
    }

    hepatizon::security::SecureString out{};
    out.resize(plainOpt->size());
    if (!out.empty())
    {
        std::memcpy(out.data(), plainOpt->data(), out.size());
    }
    hepatizon::security::secureRelease(*plainOpt);
    return out;
}

} // namespace hepatizon::core

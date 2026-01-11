#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/core/VaultHeaderAad.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/StorageErrors.hpp"
#include <chrono>
#include <cstring>

namespace hepatizon::core
{
namespace
{

[[nodiscard]] std::span<const std::byte> asBytes(std::string_view s) noexcept
{
    return std::as_bytes(std::span<const char>{ s.data(), s.size() });
}

[[nodiscard]] VaultResult<hepatizon::storage::VaultInfo>
loadVaultInfoOrError(hepatizon::storage::IStorageRepository& storage, const std::filesystem::path& vaultDir) noexcept
{
    try
    {
        hepatizon::storage::VaultInfo info{};
        info.kdf = storage.loadKdfMetadata(vaultDir);
        return info;
    }
    catch (const hepatizon::storage::VaultNotFound&)
    {
        return VaultError::NotFound;
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
}

[[nodiscard]] VaultResult<hepatizon::crypto::AeadBox>
loadEncryptedHeaderOrError(hepatizon::storage::IStorageRepository& storage, const std::filesystem::path& vaultDir,
                           std::span<const std::byte> dbKey) noexcept
{
    try
    {
        return storage.loadEncryptedHeader(vaultDir, dbKey);
    }
    catch (const hepatizon::storage::VaultNotFound&)
    {
        return VaultError::NotFound;
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
}

[[nodiscard]] std::uint64_t unixSecondsNow() noexcept
{
    using Clock = std::chrono::system_clock;
    const auto now{ Clock::now() };
    const auto secs{ std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()) };
    const auto count{ secs.count() };
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

struct ParsedHeader final
{
    VaultHeader header{};
    hepatizon::security::SecureBuffer secretsKey;
    bool shouldStoreHeader{ false };
};

[[nodiscard]] VaultResult<hepatizon::security::SecureBuffer>
deriveHeaderKeyOrError(hepatizon::crypto::ICryptoProvider& crypto, std::span<const std::uint8_t> masterKey) noexcept
{
    try
    {
        constexpr std::string_view kHeaderKeyContext{ "hepatizon.vault.header.aead_key.v1" };
        return crypto.deriveSubkey(masterKey, asBytes(kHeaderKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }
}

[[nodiscard]] VaultResult<hepatizon::security::SecureBuffer>
deriveDbKeyOrError(hepatizon::crypto::ICryptoProvider& crypto, std::span<const std::uint8_t> masterKey) noexcept
{
    try
    {
        constexpr std::string_view kDbKeyContext{ "hepatizon.vault.db.sqlcipher_key.v1" };
        return crypto.deriveSubkey(masterKey, asBytes(kDbKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }
}

[[nodiscard]] VaultResult<hepatizon::security::SecureBuffer>
decryptHeaderOrError(hepatizon::crypto::ICryptoProvider& crypto, std::span<const std::uint8_t> headerKey,
                     const hepatizon::crypto::AeadBox& encryptedHeader,
                     const hepatizon::crypto::KdfMetadata& kdf) noexcept
{
    try
    {
        const auto aad{ encodeVaultHeaderAadV1(kdf) };
        const auto plainOpt{ crypto.aeadDecrypt(headerKey, encryptedHeader,
                                                std::span<const std::byte>{ aad.data(), aad.size() }) };
        if (!plainOpt)
        {
            return VaultError::AuthFailed;
        }
        return *plainOpt;
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }
}

[[nodiscard]] VaultResult<ParsedHeader> parseHeaderAndSecretsKeyOrError(hepatizon::crypto::ICryptoProvider& crypto,
                                                                        hepatizon::security::SecureBuffer masterKey,
                                                                        std::span<const std::byte> plainBytes)
{
    ParsedHeader out{};

    if (plainBytes.size() == g_vaultHeaderV2Bytes)
    {
        out.secretsKey.resize(g_vaultSecretsKeyBytes);
        if (!decodeVaultHeaderV2(plainBytes, out.header, std::span<std::uint8_t>{ out.secretsKey }))
        {
            hepatizon::security::secureRelease(out.secretsKey);
            hepatizon::security::secureRelease(masterKey);
            return VaultError::InvalidVaultFormat;
        }
        hepatizon::security::secureRelease(masterKey);
        return out;
    }

    if (plainBytes.size() == g_vaultHeaderV1Bytes)
    {
        const auto headerOpt{ decodeVaultHeaderV1(plainBytes) };
        if (!headerOpt)
        {
            hepatizon::security::secureRelease(masterKey);
            return VaultError::InvalidVaultFormat;
        }
        out.header = *headerOpt;

        try
        {
            constexpr std::string_view kSecretsKeyContext{ "hepatizon.vault.secrets.aead_key.v1" };
            out.secretsKey =
                crypto.deriveSubkey(masterKey, asBytes(kSecretsKeyContext), hepatizon::crypto::g_aeadKeyBytes);
        }
        catch (...)
        {
            hepatizon::security::secureRelease(masterKey);
            return VaultError::UnsupportedKdfMetadata;
        }
        hepatizon::security::secureRelease(masterKey);

        out.header.headerVersion = g_vaultHeaderVersionV2;
        out.shouldStoreHeader = true;
        return out;
    }

    hepatizon::security::secureRelease(masterKey);
    return VaultError::InvalidVaultFormat;
}

[[nodiscard]] VaultResult<ParsedHeader> migrateSchemaOrError(ParsedHeader parsed) noexcept
{
    if (parsed.header.dbSchemaVersion > g_vaultDbSchemaVersionCurrent)
    {
        hepatizon::security::secureRelease(parsed.secretsKey);
        return VaultError::MigrationRequired;
    }

    if (parsed.header.dbSchemaVersion < g_vaultDbSchemaVersionCurrent)
    {
        parsed.shouldStoreHeader = true;
        while (parsed.header.dbSchemaVersion < g_vaultDbSchemaVersionCurrent)
        {
            if (parsed.header.dbSchemaVersion == g_vaultDbSchemaVersionV0 &&
                g_vaultDbSchemaVersionCurrent == g_vaultDbSchemaVersionV1)
            {
                parsed.header.dbSchemaVersion = g_vaultDbSchemaVersionV1;
                continue;
            }
            hepatizon::security::secureRelease(parsed.secretsKey);
            return VaultError::InvalidVaultFormat;
        }
    }

    return parsed;
}

[[nodiscard]] VaultResult<std::monostate>
maybeStoreUpdatedHeader(hepatizon::storage::IStorageRepository& storage, hepatizon::crypto::ICryptoProvider& crypto,
                        const std::filesystem::path& vaultDir, std::span<const std::uint8_t> headerKey,
                        const hepatizon::crypto::KdfMetadata& kdf, const VaultHeader& header,
                        std::span<const std::uint8_t> secretsKey, bool shouldStoreHeader,
                        std::span<const std::byte> dbKey) noexcept
{
    if (!shouldStoreHeader)
    {
        return std::monostate{};
    }
    if (secretsKey.size() != g_vaultSecretsKeyBytes)
    {
        return VaultError::InvalidVaultFormat;
    }

    hepatizon::crypto::AeadBox reEncrypted{};
    try
    {
        const auto updatedPlain{ encodeVaultHeaderV2(header, secretsKey) };
        const auto aad{ encodeVaultHeaderAadV1(kdf) };
        reEncrypted =
            crypto.aeadEncrypt(headerKey, std::span<const std::byte>{ updatedPlain.data(), updatedPlain.size() },
                               std::span<const std::byte>{ aad.data(), aad.size() });
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }

    try
    {
        storage.storeEncryptedHeader(vaultDir, reEncrypted, dbKey);
    }
    catch (...)
    {
        return VaultError::StorageError;
    }

    return std::monostate{};
}

} // namespace

VaultService::VaultService(hepatizon::crypto::ICryptoProvider& crypto,
                           hepatizon::storage::IStorageRepository& storage) noexcept
    : m_crypto(&crypto), m_storage(&storage)
{
}

[[nodiscard]] bool VaultService::vaultExists(const std::filesystem::path& vaultDir) const noexcept
{
    try
    {
        return m_storage->vaultExists(vaultDir);
    }
    catch (...)
    {
        return false;
    }
}

[[nodiscard]] VaultResult<CreatedVault>
VaultService::createVault(const std::filesystem::path& vaultDir,
                          const hepatizon::security::SecureString& password) noexcept
{
    return createVault(vaultDir, password, hepatizon::core::defaultArgon2idParams());
}

[[nodiscard]] VaultResult<CreatedVault> VaultService::createVault(const std::filesystem::path& vaultDir,
                                                                  const hepatizon::security::SecureString& password,
                                                                  const hepatizon::crypto::Argon2idParams& params)
{
    const auto metaOpt{ hepatizon::core::makeKdfMetadata(params) };
    if (!metaOpt)
    {
        return VaultError::RandomFailed;
    }
    const auto meta{ *metaOpt };

    hepatizon::security::SecureBuffer masterKey{};
    try
    {
        masterKey = m_crypto->deriveMasterKey(hepatizon::security::asBytes(password), meta);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }

    hepatizon::security::SecureBuffer headerKey{};
    try
    {
        constexpr std::string_view kHeaderKeyContext{ "hepatizon.vault.header.aead_key.v1" };
        headerKey = m_crypto->deriveSubkey(masterKey, asBytes(kHeaderKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        hepatizon::security::secureRelease(masterKey);
        return VaultError::UnsupportedKdfMetadata;
    }

    hepatizon::security::SecureBuffer dbKey{};
    try
    {
        constexpr std::string_view kDbKeyContext{ "hepatizon.vault.db.sqlcipher_key.v1" };
        dbKey = m_crypto->deriveSubkey(masterKey, asBytes(kDbKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        hepatizon::security::secureRelease(masterKey);
        hepatizon::security::secureRelease(headerKey);
        return VaultError::UnsupportedKdfMetadata;
    }
    hepatizon::security::secureRelease(masterKey);

    VaultHeader header{};
    header.headerVersion = g_vaultHeaderVersionV2;
    header.createdAtUnixSeconds = unixSecondsNow();
    header.dbSchemaVersion = g_vaultDbSchemaVersionCurrent;
    header.flags = 0U;
    if (!fillRandom(*m_crypto, std::span<std::uint8_t>{ header.vaultId }))
    {
        hepatizon::security::secureRelease(headerKey);
        return VaultError::RandomFailed;
    }

    hepatizon::security::SecureBuffer secretsKey{};
    secretsKey.resize(g_vaultSecretsKeyBytes);
    if (!fillRandom(*m_crypto, std::span<std::uint8_t>{ secretsKey }))
    {
        hepatizon::security::secureRelease(secretsKey);
        hepatizon::security::secureRelease(headerKey);
        return VaultError::RandomFailed;
    }

    const auto plain{ encodeVaultHeaderV2(header, std::span<const std::uint8_t>{ secretsKey }) };
    const auto aad{ encodeVaultHeaderAadV1(meta) };
    hepatizon::crypto::AeadBox encrypted{};
    try
    {
        encrypted = m_crypto->aeadEncrypt(headerKey, std::span<const std::byte>{ plain.data(), plain.size() },
                                          std::span<const std::byte>{ aad.data(), aad.size() });
    }
    catch (...)
    {
        hepatizon::security::secureRelease(secretsKey);
        hepatizon::security::secureRelease(headerKey);
        return VaultError::CryptoError;
    }

    hepatizon::storage::VaultInfo info{};
    info.kdf = meta;
    info.encryptedHeader = encrypted;

    try
    {
        m_storage->createVault(vaultDir, info, hepatizon::security::asBytes(dbKey));
    }
    catch (...)
    {
        hepatizon::security::secureRelease(secretsKey);
        hepatizon::security::secureRelease(headerKey);
        hepatizon::security::secureRelease(dbKey);
        return VaultError::StorageError;
    }

    hepatizon::security::secureRelease(secretsKey);
    hepatizon::security::secureRelease(headerKey);
    hepatizon::security::secureRelease(dbKey);
    return CreatedVault{ meta, header };
}

[[nodiscard]] VaultResult<UnlockedVault>
VaultService::openVault(const std::filesystem::path& vaultDir,
                        const hepatizon::security::SecureString& password) noexcept
{
    const auto infoOrErr{ loadVaultInfoOrError(*m_storage, vaultDir) };
    if (std::holds_alternative<VaultError>(infoOrErr))
    {
        return std::get<VaultError>(infoOrErr);
    }
    const auto info{ std::get<hepatizon::storage::VaultInfo>(infoOrErr) };

    hepatizon::security::SecureBuffer masterKey{};
    try
    {
        masterKey = m_crypto->deriveMasterKey(hepatizon::security::asBytes(password), info.kdf);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }

    const auto headerKeyOrErr{ deriveHeaderKeyOrError(*m_crypto, masterKey) };
    if (std::holds_alternative<VaultError>(headerKeyOrErr))
    {
        hepatizon::security::secureRelease(masterKey);
        return std::get<VaultError>(headerKeyOrErr);
    }
    auto headerKey{ std::get<hepatizon::security::SecureBuffer>(headerKeyOrErr) };

    const auto dbKeyOrErr{ deriveDbKeyOrError(*m_crypto, masterKey) };
    if (std::holds_alternative<VaultError>(dbKeyOrErr))
    {
        hepatizon::security::secureRelease(masterKey);
        hepatizon::security::secureRelease(headerKey);
        return std::get<VaultError>(dbKeyOrErr);
    }
    auto dbKey{ std::get<hepatizon::security::SecureBuffer>(dbKeyOrErr) };

    const auto encryptedHeaderOrErr{ loadEncryptedHeaderOrError(*m_storage, vaultDir,
                                                                hepatizon::security::asBytes(dbKey)) };
    if (std::holds_alternative<VaultError>(encryptedHeaderOrErr))
    {
        hepatizon::security::secureRelease(masterKey);
        hepatizon::security::secureRelease(headerKey);
        hepatizon::security::secureRelease(dbKey);
        return std::get<VaultError>(encryptedHeaderOrErr);
    }
    const auto encryptedHeader{ std::get<hepatizon::crypto::AeadBox>(encryptedHeaderOrErr) };

    const auto plainOrErr{ decryptHeaderOrError(*m_crypto, headerKey, encryptedHeader, info.kdf) };
    if (std::holds_alternative<VaultError>(plainOrErr))
    {
        hepatizon::security::secureRelease(masterKey);
        hepatizon::security::secureRelease(headerKey);
        hepatizon::security::secureRelease(dbKey);
        return std::get<VaultError>(plainOrErr);
    }
    auto plain{ std::get<hepatizon::security::SecureBuffer>(plainOrErr) };
    const auto parsedOrErr{ parseHeaderAndSecretsKeyOrError(*m_crypto, std::move(masterKey),
                                                            hepatizon::security::asBytes(plain)) };
    hepatizon::security::secureRelease(plain);
    if (std::holds_alternative<VaultError>(parsedOrErr))
    {
        hepatizon::security::secureRelease(headerKey);
        return std::get<VaultError>(parsedOrErr);
    }
    auto parsed{ std::get<ParsedHeader>(parsedOrErr) };

    const auto migratedOrErr{ migrateSchemaOrError(std::move(parsed)) };
    if (std::holds_alternative<VaultError>(migratedOrErr))
    {
        hepatizon::security::secureRelease(headerKey);
        hepatizon::security::secureRelease(dbKey);
        return std::get<VaultError>(migratedOrErr);
    }
    parsed = std::get<ParsedHeader>(migratedOrErr);

    const auto storedOrErr{ maybeStoreUpdatedHeader(*m_storage, *m_crypto, vaultDir, headerKey, info.kdf, parsed.header,
                                                    parsed.secretsKey, parsed.shouldStoreHeader,
                                                    hepatizon::security::asBytes(dbKey)) };
    if (std::holds_alternative<VaultError>(storedOrErr))
    {
        hepatizon::security::secureRelease(headerKey);
        hepatizon::security::secureRelease(parsed.secretsKey);
        hepatizon::security::secureRelease(dbKey);
        return std::get<VaultError>(storedOrErr);
    }

    return UnlockedVault{ info.kdf, parsed.header, std::move(headerKey), std::move(parsed.secretsKey),
                          std::move(dbKey) };
}

[[nodiscard]] VaultResult<UnlockedVault>
VaultService::rekeyVault(const std::filesystem::path& vaultDir, UnlockedVault&& v,
                         const hepatizon::security::SecureString& newPassword) noexcept
{
    return rekeyVault(vaultDir, std::move(v), newPassword, hepatizon::core::defaultArgon2idParams());
}

[[nodiscard]] VaultResult<UnlockedVault>
VaultService::rekeyVault(const std::filesystem::path& vaultDir, UnlockedVault&& v,
                         const hepatizon::security::SecureString& newPassword,
                         const hepatizon::crypto::Argon2idParams& params) noexcept
{
    const auto newMetaOpt{ hepatizon::core::makeKdfMetadata(params) };
    if (!newMetaOpt)
    {
        return VaultError::RandomFailed;
    }
    const auto newMeta{ *newMetaOpt };

    hepatizon::security::SecureBuffer newMasterKey{};
    try
    {
        newMasterKey = m_crypto->deriveMasterKey(hepatizon::security::asBytes(newPassword), newMeta);
    }
    catch (...)
    {
        return VaultError::UnsupportedKdfMetadata;
    }

    hepatizon::security::SecureBuffer newHeaderKey{};
    try
    {
        constexpr std::string_view kHeaderKeyContext{ "hepatizon.vault.header.aead_key.v1" };
        newHeaderKey =
            m_crypto->deriveSubkey(newMasterKey, asBytes(kHeaderKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        hepatizon::security::secureRelease(newMasterKey);
        return VaultError::UnsupportedKdfMetadata;
    }

    hepatizon::security::SecureBuffer newDbKey{};
    try
    {
        constexpr std::string_view kDbKeyContext{ "hepatizon.vault.db.sqlcipher_key.v1" };
        newDbKey = m_crypto->deriveSubkey(newMasterKey, asBytes(kDbKeyContext), hepatizon::crypto::g_aeadKeyBytes);
    }
    catch (...)
    {
        hepatizon::security::secureRelease(newMasterKey);
        hepatizon::security::secureRelease(newHeaderKey);
        return VaultError::UnsupportedKdfMetadata;
    }

    hepatizon::security::secureRelease(newMasterKey);

    auto header{ v.header() };
    header.headerVersion = g_vaultHeaderVersionV2;

    if (v.secretsKey().size() != g_vaultSecretsKeyBytes)
    {
        hepatizon::security::secureRelease(newHeaderKey);
        return VaultError::InvalidVaultFormat;
    }

    hepatizon::crypto::AeadBox encrypted{};
    try
    {
        const auto plain{ encodeVaultHeaderV2(header, std::span<const std::uint8_t>{ v.secretsKey() }) };
        const auto aad{ encodeVaultHeaderAadV1(newMeta) };
        encrypted = m_crypto->aeadEncrypt(newHeaderKey, std::span<const std::byte>{ plain.data(), plain.size() },
                                          std::span<const std::byte>{ aad.data(), aad.size() });
    }
    catch (...)
    {
        hepatizon::security::secureRelease(newHeaderKey);
        return VaultError::CryptoError;
    }

    try
    {
        m_storage->storeKdfMetadata(vaultDir, newMeta);
        m_storage->storeEncryptedHeader(vaultDir, encrypted, hepatizon::security::asBytes(v.dbKey()));
        m_storage->rekeyDb(vaultDir, hepatizon::security::asBytes(v.dbKey()), hepatizon::security::asBytes(newDbKey));
    }
    catch (const hepatizon::storage::VaultNotFound&)
    {
        hepatizon::security::secureRelease(newHeaderKey);
        hepatizon::security::secureRelease(newDbKey);
        return VaultError::NotFound;
    }
    catch (...)
    {
        // Best-effort rollback: restore old metadata if we already wrote the new one.
        try
        {
            try
            {
                const auto plain{ encodeVaultHeaderV2(header, std::span<const std::uint8_t>{ v.secretsKey() }) };
                const auto aad{ encodeVaultHeaderAadV1(v.kdf()) };
                const auto oldEncrypted =
                    m_crypto->aeadEncrypt(v.headerKey(), std::span<const std::byte>{ plain.data(), plain.size() },
                                          std::span<const std::byte>{ aad.data(), aad.size() });
                m_storage->storeEncryptedHeader(vaultDir, oldEncrypted, hepatizon::security::asBytes(v.dbKey()));
            }
            catch (...)
            {
            }
            m_storage->storeKdfMetadata(vaultDir, v.kdf());
        }
        catch (...)
        {
        }
        hepatizon::security::secureRelease(newHeaderKey);
        hepatizon::security::secureRelease(newDbKey);
        return VaultError::StorageError;
    }

    auto secretsKey{ v.takeSecretsKey() };
    return UnlockedVault{ newMeta, header, std::move(newHeaderKey), std::move(secretsKey), std::move(newDbKey) };
}

[[nodiscard]] VaultResult<std::monostate>
VaultService::putSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key,
                        const hepatizon::security::SecureString& value) noexcept
{
    if (key.empty())
    {
        return VaultError::InvalidVaultFormat;
    }

    const auto keyChars{ std::span<const char>{ key.data(), key.size() } };
    const auto aad{ std::as_bytes(keyChars) };

    hepatizon::crypto::AeadBox encrypted{};
    try
    {
        encrypted = m_crypto->aeadEncrypt(v.secretsKey(), hepatizon::security::asBytes(value), aad);
    }
    catch (...)
    {
        return VaultError::CryptoError;
    }

    try
    {
        m_storage->storeBlob(vaultDir, key, encrypted, hepatizon::security::asBytes(v.dbKey()));
    }
    catch (...)
    {
        return VaultError::StorageError;
    }

    return std::monostate{};
}

[[nodiscard]] VaultResult<hepatizon::security::SecureString>
VaultService::getSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key)
{
    if (key.empty())
    {
        return VaultError::InvalidVaultFormat;
    }

    std::optional<hepatizon::crypto::AeadBox> boxOpt{};
    try
    {
        boxOpt = m_storage->loadBlob(vaultDir, key, hepatizon::security::asBytes(v.dbKey()));
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
    if (!boxOpt)
    {
        return VaultError::NotFound;
    }

    const auto keyChars{ std::span<const char>{ key.data(), key.size() } };
    const auto aad{ std::as_bytes(keyChars) };

    std::optional<hepatizon::security::SecureBuffer> plainOpt{};
    try
    {
        plainOpt = m_crypto->aeadDecrypt(v.secretsKey(), *boxOpt, aad);
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

[[nodiscard]] VaultResult<std::vector<std::string>> VaultService::listSecretKeys(const std::filesystem::path& vaultDir,
                                                                                 const UnlockedVault& v) noexcept
{
    try
    {
        return m_storage->listBlobKeys(vaultDir, hepatizon::security::asBytes(v.dbKey()));
    }
    catch (const hepatizon::storage::VaultNotFound&)
    {
        return VaultError::NotFound;
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
}

[[nodiscard]] VaultResult<std::monostate>
VaultService::deleteSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key) noexcept
{
    if (key.empty())
    {
        return VaultError::InvalidVaultFormat;
    }

    try
    {
        if (!m_storage->deleteBlob(vaultDir, key, hepatizon::security::asBytes(v.dbKey())))
        {
            return VaultError::NotFound;
        }
        return std::monostate{};
    }
    catch (const hepatizon::storage::VaultNotFound&)
    {
        return VaultError::NotFound;
    }
    catch (...)
    {
        return VaultError::StorageError;
    }
}

} // namespace hepatizon::core

#ifndef INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP
#define INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP

#include "hepatizon/core/VaultHeader.hpp"
#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/IStorageRepository.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hepatizon::core
{

enum class VaultError : std::uint8_t
{
    RandomFailed,
    StorageError,
    InvalidVaultFormat,
    NotFound,
    MigrationRequired,
    UnsupportedKdfMetadata,
    AuthFailed,
    CryptoError,
};

template <class T> using VaultResult = std::variant<T, VaultError>;

struct CreatedVault final
{
public:
    CreatedVault() = default;
    CreatedVault(hepatizon::crypto::KdfMetadata kdf, VaultHeader header) noexcept : m_kdf(kdf), m_header(header)
    {
    }

    [[nodiscard]] const hepatizon::crypto::KdfMetadata& kdf() const noexcept
    {
        return m_kdf;
    }
    [[nodiscard]] const VaultHeader& header() const noexcept
    {
        return m_header;
    }

private:
    hepatizon::crypto::KdfMetadata m_kdf{};
    VaultHeader m_header{};
};

class UnlockedVault final
{
public:
    UnlockedVault() = default;
    UnlockedVault(const UnlockedVault&) = delete;
    UnlockedVault& operator=(const UnlockedVault&) = delete;
    UnlockedVault(UnlockedVault&& other) noexcept
        : m_kdf(other.m_kdf), m_header(other.m_header), m_headerKey{}, m_secretsKey{}
    {
        m_headerKey.swap(other.m_headerKey);
        m_secretsKey.swap(other.m_secretsKey);
        other.m_kdf = {};
        other.m_header = {};
    }

    UnlockedVault& operator=(UnlockedVault&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }

        m_kdf = other.m_kdf;
        m_header = other.m_header;

        hepatizon::security::secureRelease(m_headerKey);
        hepatizon::security::secureRelease(m_secretsKey);
        m_headerKey.swap(other.m_headerKey);
        m_secretsKey.swap(other.m_secretsKey);

        other.m_kdf = {};
        other.m_header = {};
        return *this;
    }

    ~UnlockedVault() noexcept
    {
        hepatizon::security::secureRelease(m_headerKey);
        hepatizon::security::secureRelease(m_secretsKey);
    }

    UnlockedVault(hepatizon::crypto::KdfMetadata kdf, VaultHeader header, hepatizon::security::SecureBuffer headerKey,
                  hepatizon::security::SecureBuffer secretsKey) noexcept
        : m_kdf(kdf), m_header(header), m_headerKey(std::move(headerKey)), m_secretsKey(std::move(secretsKey))
    {
    }

    [[nodiscard]] const hepatizon::crypto::KdfMetadata& kdf() const noexcept
    {
        return m_kdf;
    }
    [[nodiscard]] const VaultHeader& header() const noexcept
    {
        return m_header;
    }
    [[nodiscard]] const hepatizon::security::SecureBuffer& headerKey() const noexcept
    {
        return m_headerKey;
    }

    [[nodiscard]] const hepatizon::security::SecureBuffer& secretsKey() const noexcept
    {
        return m_secretsKey;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer takeSecretsKey() noexcept
    {
        hepatizon::security::SecureBuffer out{};
        out.swap(m_secretsKey);
        return out;
    }

private:
    hepatizon::crypto::KdfMetadata m_kdf{};
    VaultHeader m_header{};
    hepatizon::security::SecureBuffer m_headerKey;
    hepatizon::security::SecureBuffer m_secretsKey;
};

class VaultService final
{
public:
    VaultService(hepatizon::crypto::ICryptoProvider& crypto, hepatizon::storage::IStorageRepository& storage) noexcept;

    [[nodiscard]] bool vaultExists(const std::filesystem::path& vaultDir) const noexcept;

    [[nodiscard]] VaultResult<CreatedVault> createVault(const std::filesystem::path& vaultDir,
                                                        const hepatizon::security::SecureString& password) noexcept;

    [[nodiscard]] VaultResult<CreatedVault> createVault(const std::filesystem::path& vaultDir,
                                                        const hepatizon::security::SecureString& password,
                                                        const hepatizon::crypto::Argon2idParams& params);

    // Opens an existing vault: derives keys, decrypts the header, and auto-migrates supported older schemas.
    [[nodiscard]] VaultResult<UnlockedVault> openVault(const std::filesystem::path& vaultDir,
                                                       const hepatizon::security::SecureString& password) noexcept;

    // Changes the password/KDF metadata without re-encrypting stored secrets (secrets are protected by the DEK).
    [[nodiscard]] VaultResult<UnlockedVault> rekeyVault(const std::filesystem::path& vaultDir, UnlockedVault&& v,
                                                        const hepatizon::security::SecureString& newPassword) noexcept;

    [[nodiscard]] VaultResult<UnlockedVault> rekeyVault(const std::filesystem::path& vaultDir, UnlockedVault&& v,
                                                        const hepatizon::security::SecureString& newPassword,
                                                        const hepatizon::crypto::Argon2idParams& params) noexcept;

    [[nodiscard]] VaultResult<std::monostate> putSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v,
                                                        std::string_view key,
                                                        const hepatizon::security::SecureString& value) noexcept;

    [[nodiscard]] VaultResult<hepatizon::security::SecureString>
    getSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key);

    // Lists user blob keys (does not decrypt values).
    [[nodiscard]] VaultResult<std::vector<std::string>> listSecretKeys(const std::filesystem::path& vaultDir,
                                                                       const UnlockedVault& v) noexcept;

    // Deletes a secret value. Returns NotFound if key does not exist.
    [[nodiscard]] VaultResult<std::monostate> deleteSecret(const std::filesystem::path& vaultDir,
                                                           const UnlockedVault& v, std::string_view key) noexcept;

private:
    hepatizon::crypto::ICryptoProvider* m_crypto{ nullptr };
    hepatizon::storage::IStorageRepository* m_storage{ nullptr };
};

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP

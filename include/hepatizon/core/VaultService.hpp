#ifndef INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP
#define INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP

#include "hepatizon/core/VaultHeader.hpp"
#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/IStorageRepository.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include <variant>

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
    CreatedVault(hepatizon::crypto::KdfMetadata kdf, VaultHeaderV1 header) noexcept : m_kdf(kdf), m_header(header)
    {
    }

    [[nodiscard]] const hepatizon::crypto::KdfMetadata& kdf() const noexcept
    {
        return m_kdf;
    }
    [[nodiscard]] const VaultHeaderV1& header() const noexcept
    {
        return m_header;
    }

private:
    hepatizon::crypto::KdfMetadata m_kdf{};
    VaultHeaderV1 m_header{};
};

class UnlockedVault final
{
public:
    UnlockedVault() = default;
    UnlockedVault(const UnlockedVault&) = delete;
    UnlockedVault& operator=(const UnlockedVault&) = delete;
    UnlockedVault(UnlockedVault&&) noexcept = default;
    UnlockedVault& operator=(UnlockedVault&&) noexcept = default;
    ~UnlockedVault() = default;

    UnlockedVault(hepatizon::crypto::KdfMetadata kdf, VaultHeaderV1 header,
                  hepatizon::security::SecureBuffer masterKey) noexcept
        : m_kdf(kdf), m_header(header), m_masterKey(std::move(masterKey))
    {
    }

    [[nodiscard]] const hepatizon::crypto::KdfMetadata& kdf() const noexcept
    {
        return m_kdf;
    }
    [[nodiscard]] const VaultHeaderV1& header() const noexcept
    {
        return m_header;
    }
    [[nodiscard]] const hepatizon::security::SecureBuffer& masterKey() const noexcept
    {
        return m_masterKey;
    }

private:
    hepatizon::crypto::KdfMetadata m_kdf{};
    VaultHeaderV1 m_header{};
    hepatizon::security::SecureBuffer m_masterKey;
};

class VaultService final
{
public:
    VaultService(hepatizon::crypto::ICryptoProvider& crypto, hepatizon::storage::IStorageRepository& storage) noexcept;

    [[nodiscard]] VaultResult<CreatedVault> createVault(const std::filesystem::path& vaultDir,
                                                        std::span<const std::byte> password) noexcept;

    [[nodiscard]] VaultResult<CreatedVault> createVault(const std::filesystem::path& vaultDir,
                                                        std::span<const std::byte> password,
                                                        const hepatizon::crypto::Argon2idParams& params) noexcept;

    [[nodiscard]] VaultResult<UnlockedVault> unlockVault(const std::filesystem::path& vaultDir,
                                                         std::span<const std::byte> password);

    [[nodiscard]] VaultResult<std::monostate> putSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v,
                                                        std::string_view key,
                                                        const hepatizon::security::SecureString& value) noexcept;

    [[nodiscard]] VaultResult<hepatizon::security::SecureString>
    getSecret(const std::filesystem::path& vaultDir, const UnlockedVault& v, std::string_view key) noexcept;

private:
    hepatizon::crypto::ICryptoProvider* m_crypto{ nullptr };
    hepatizon::storage::IStorageRepository* m_storage{ nullptr };
};

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_VAULTSERVICE_HPP

#ifndef INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP
#define INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/crypto/KdfMetadata.hpp"
#include <filesystem>
#include <optional>
#include <string_view>

namespace hepatizon::storage
{

struct VaultInfo final
{
    hepatizon::crypto::KdfMetadata kdf{};
    hepatizon::crypto::AeadBox encryptedHeader{};
};

class IStorageRepository
{
public:
    IStorageRepository() = default;
    IStorageRepository(const IStorageRepository&) = delete;
    IStorageRepository& operator=(const IStorageRepository&) = delete;
    IStorageRepository(IStorageRepository&&) = delete;
    IStorageRepository& operator=(IStorageRepository&&) = delete;
    virtual ~IStorageRepository() = default;

    virtual void createVault(const std::filesystem::path& vaultDir, const VaultInfo& info) = 0;

    [[nodiscard]] virtual VaultInfo loadVaultInfo(const std::filesystem::path& vaultDir) const = 0;

    virtual void storeEncryptedHeader(const std::filesystem::path& vaultDir,
                                      const hepatizon::crypto::AeadBox& encryptedHeader) = 0;

    virtual void storeBlob(const std::filesystem::path& vaultDir, std::string_view key,
                           const hepatizon::crypto::AeadBox& value) = 0;

    [[nodiscard]] virtual std::optional<hepatizon::crypto::AeadBox> loadBlob(const std::filesystem::path& vaultDir,
                                                                             std::string_view key) const = 0;
};

} // namespace hepatizon::storage

#endif // INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP

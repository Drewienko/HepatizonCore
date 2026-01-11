#ifndef INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP
#define INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/crypto/KdfMetadata.hpp"
#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

    [[nodiscard]] virtual bool vaultExists(const std::filesystem::path& vaultDir) const = 0;

    // Creates a new vault directory with metadata and an initialized database.
    // When SQLCipher is enabled, `dbKey` must be non-empty and is used to encrypt the DB file.
    virtual void createVault(const std::filesystem::path& vaultDir, const VaultInfo& info,
                             std::span<const std::byte> dbKey) = 0;

    // Loads only KDF metadata (from the plaintext meta file).
    [[nodiscard]] virtual hepatizon::crypto::KdfMetadata
    loadKdfMetadata(const std::filesystem::path& vaultDir) const = 0;

    virtual void storeKdfMetadata(const std::filesystem::path& vaultDir, const hepatizon::crypto::KdfMetadata& kdf) = 0;

    // Loads/stores the encrypted vault header stored inside the DB.
    [[nodiscard]] virtual hepatizon::crypto::AeadBox loadEncryptedHeader(const std::filesystem::path& vaultDir,
                                                                         std::span<const std::byte> dbKey) const = 0;

    virtual void storeEncryptedHeader(const std::filesystem::path& vaultDir, const hepatizon::crypto::AeadBox& header,
                                      std::span<const std::byte> dbKey) = 0;

    // Rekeys the underlying DB file (no-op when SQLCipher is disabled).
    virtual void rekeyDb(const std::filesystem::path& vaultDir, std::span<const std::byte> oldDbKey,
                         std::span<const std::byte> newDbKey) = 0;

    virtual void storeBlob(const std::filesystem::path& vaultDir, std::string_view key,
                           const hepatizon::crypto::AeadBox& value, std::span<const std::byte> dbKey) = 0;

    [[nodiscard]] virtual std::optional<hepatizon::crypto::AeadBox>
    loadBlob(const std::filesystem::path& vaultDir, std::string_view key, std::span<const std::byte> dbKey) const = 0;

    [[nodiscard]] virtual std::vector<std::string> listBlobKeys(const std::filesystem::path& vaultDir,
                                                                std::span<const std::byte> dbKey) const = 0;

    // Returns true if a row was deleted, false if it was not found.
    [[nodiscard]] virtual bool deleteBlob(const std::filesystem::path& vaultDir, std::string_view key,
                                          std::span<const std::byte> dbKey) = 0;
};

} // namespace hepatizon::storage

#endif // INCLUDE_HEPATIZON_STORAGE_ISTORAGEREPOSITORY_HPP

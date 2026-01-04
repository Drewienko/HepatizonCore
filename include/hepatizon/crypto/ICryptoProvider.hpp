#ifndef INCLUDE_HEPATIZON_CRYPTO_ICRYPTOPROVIDER_HPP
#define INCLUDE_HEPATIZON_CRYPTO_ICRYPTOPROVIDER_HPP

#include "hepatizon/crypto/KdfMetadata.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace hepatizon::crypto
{

constexpr std::size_t g_aeadKeyBytes{ 32 };
constexpr std::size_t g_aeadNonceBytes{ 12 };
constexpr std::size_t g_aeadTagBytes{ 16 };

struct AeadBox final
{
    std::array<std::uint8_t, g_aeadNonceBytes> nonce{};
    std::array<std::uint8_t, g_aeadTagBytes> tag{};
    std::vector<std::uint8_t> cipherText;
};

class ICryptoProvider
{
public:
    ICryptoProvider() = default;
    ICryptoProvider(const ICryptoProvider&) = delete;
    ICryptoProvider& operator=(const ICryptoProvider&) = delete;
    ICryptoProvider(ICryptoProvider&&) = delete;
    ICryptoProvider& operator=(ICryptoProvider&&) = delete;
    virtual ~ICryptoProvider() = default;

    // Derives the master key from persisted vault metadata.
    // Contract violations (unsupported algorithm/version/params) may throw std::invalid_argument.
    [[nodiscard]] virtual hepatizon::security::SecureBuffer
    deriveMasterKey(std::span<const std::byte> password, const hepatizon::crypto::KdfMetadata& meta) const = 0;

    [[nodiscard]] virtual bool randomBytes(std::span<std::uint8_t> out) noexcept = 0;

    // AEAD: ChaCha20-Poly1305 (IETF, 12-byte nonce).
    // Returns std::nullopt on authentication failure.
    [[nodiscard]] virtual AeadBox aeadEncrypt(std::span<const std::uint8_t> key, std::span<const std::byte> plainText,
                                              std::span<const std::byte> associatedData) = 0;

    [[nodiscard]] virtual std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt(std::span<const std::uint8_t> key, const AeadBox& box, std::span<const std::byte> associatedData) = 0;
};

} // namespace hepatizon::crypto

#endif // INCLUDE_HEPATIZON_CRYPTO_ICRYPTOPROVIDER_HPP

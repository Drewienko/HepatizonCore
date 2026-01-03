#include "hepatizon/crypto/KeyDerivation.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureRandom.hpp"
#include "monocypher.h"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace hepatizon::crypto::providers
{
namespace
{

std::span<const std::byte> asBytes(std::span<const std::uint8_t> s) noexcept
{
    return std::as_bytes(s);
}

std::span<const std::uint8_t> asU8(std::span<const std::byte> s) noexcept
{
    return { reinterpret_cast<const std::uint8_t*>(s.data()), s.size() };
}

void requireExactSize(std::span<const std::uint8_t> s, std::size_t expected, const char* what)
{
    if (s.size() != expected)
    {
        throw std::invalid_argument(what);
    }
}

void requirePolicySupported(const hepatizon::crypto::KdfMetadata& meta)
{
    if (meta.policyVersion != hepatizon::crypto::g_kKdfPolicyVersion)
    {
        throw std::invalid_argument("deriveMasterKey: unsupported policyVersion");
    }
    if (meta.algorithm != hepatizon::crypto::KdfAlgorithm::Argon2id)
    {
        throw std::invalid_argument("deriveMasterKey: unsupported algorithm");
    }
    if (meta.argon2Version != hepatizon::crypto::g_kArgon2VersionV13)
    {
        throw std::invalid_argument("deriveMasterKey: unsupported Argon2 version");
    }
    if (meta.derivedKeyBytes != hepatizon::crypto::g_kMasterKeyBytes)
    {
        throw std::invalid_argument("deriveMasterKey: unsupported derivedKeyBytes");
    }
}

class NativeCryptoProvider final : public hepatizon::crypto::ICryptoProvider
{
public:
    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey(std::span<const std::byte> password, const hepatizon::crypto::KdfMetadata& meta) const override
    {
        requirePolicySupported(meta);

        const auto saltBytes = std::span<const std::uint8_t>{ meta.salt };
        return hepatizon::crypto::deriveMasterKeyArgon2id(password, asBytes(saltBytes), meta.argon2id);
    }

    [[nodiscard]] bool randomBytes(std::span<std::uint8_t> out) noexcept override
    {
        return hepatizon::security::secureRandomFill(out);
    }

    [[nodiscard]] hepatizon::crypto::AeadBox aeadEncrypt(std::span<const std::uint8_t> key,
                                                         std::span<const std::byte> plainText,
                                                         std::span<const std::byte> associatedData) override
    {
        requireExactSize(key, hepatizon::crypto::g_aeadKeyBytes, "aeadEncrypt: key");

        hepatizon::crypto::AeadBox box{};
        if (!randomBytes(std::span<std::uint8_t>{ box.nonce }))
        {
            throw std::runtime_error("aeadEncrypt: CSPRNG failure");
        }

        box.cipherText.resize(plainText.size());

        crypto_aead_ctx ctx{};
        auto wipeCtx = hepatizon::security::scopeWipe(std::as_writable_bytes(std::span{ &ctx, 1 }));
        crypto_aead_init_ietf(&ctx, key.data(), box.nonce.data());
        crypto_aead_write(&ctx, box.cipherText.data(), box.tag.data(), asU8(associatedData).data(),
                          associatedData.size(), asU8(plainText).data(), plainText.size());

        return box;
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt(std::span<const std::uint8_t> key, const hepatizon::crypto::AeadBox& box,
                std::span<const std::byte> associatedData) override
    {
        requireExactSize(key, hepatizon::crypto::g_aeadKeyBytes, "aeadDecrypt: key");
        if (box.cipherText.size() > std::numeric_limits<std::uint32_t>::max())
        {
            throw std::invalid_argument("aeadDecrypt: cipherText too large");
        }

        hepatizon::security::SecureBuffer plainText{};
        plainText.resize(box.cipherText.size());

        crypto_aead_ctx ctx{};
        auto wipeCtx = hepatizon::security::scopeWipe(std::as_writable_bytes(std::span{ &ctx, 1 }));
        crypto_aead_init_ietf(&ctx, key.data(), box.nonce.data());
        const int ok = crypto_aead_read(&ctx, plainText.data(), box.tag.data(), asU8(associatedData).data(),
                                        associatedData.size(), box.cipherText.data(), box.cipherText.size());
        if (ok != 0)
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }

        return plainText;
    }
};

} // namespace

[[nodiscard]] std::unique_ptr<hepatizon::crypto::ICryptoProvider> makeNativeCryptoProvider()
{
    return std::make_unique<NativeCryptoProvider>();
}

} // namespace hepatizon::crypto::providers

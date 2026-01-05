#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureRandom.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace hepatizon::crypto::providers
{
namespace
{

constexpr const char* g_kKdfParamArgon2Memcost{ "memcost" };
constexpr const char* g_kKdfParamArgon2Lanes{ "lanes" };
constexpr const char* g_kKdfParamThreads{ "threads" };
constexpr const char* g_kKdfParamArgon2Version{ "version" };

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

void requireArgon2idParamsSafe(const hepatizon::crypto::Argon2idParams& params)
{
    if (params.iterations == 0U || params.parallelism == 0U)
    {
        throw std::invalid_argument("deriveMasterKey: invalid Argon2id parameters");
    }

    constexpr std::uint32_t parallelismCap{ 16U };
    constexpr std::uint32_t memoryKiBCap{ 1024U * 1024U };
    constexpr std::uint32_t iterationsCap{ 10U };
    if (params.parallelism > parallelismCap || params.memoryKiB > memoryKiBCap || params.iterations > iterationsCap)
    {
        throw std::invalid_argument("deriveMasterKey: unsafe Argon2id parameters");
    }

    if (const std::uint32_t minMemoryKiB{ params.parallelism * 8U }; params.memoryKiB < minMemoryKiB)
    {
        throw std::invalid_argument("deriveMasterKey: invalid Argon2id parameters");
    }

    const std::uint32_t memoryMultiple{ params.parallelism * 4U };
    if ((params.memoryKiB % memoryMultiple) != 0U)
    {
        throw std::invalid_argument("deriveMasterKey: invalid Argon2id parameters");
    }
}

using EvpKdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using EvpMacPtr = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using EvpMacCtxPtr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

EvpKdfPtr fetchArgon2idKdf()
{
    if (EVP_KDF * kdf{ EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr) }; kdf != nullptr)
    {
        return EvpKdfPtr{ kdf, &EVP_KDF_free };
    }
    return EvpKdfPtr{ nullptr, &EVP_KDF_free };
}

EvpMacPtr fetchBlake2bMac()
{
    // OpenSSL MAC algorithm names are string-based. Try common variants.
    constexpr std::array<const char*, 2> kNames{ "BLAKE2BMAC", "BLAKE2B-MAC" };
    for (const char* name : kNames)
    {
        if (EVP_MAC * mac{ EVP_MAC_fetch(nullptr, name, nullptr) }; mac != nullptr)
        {
            return EvpMacPtr{ mac, &EVP_MAC_free };
        }
    }
    return EvpMacPtr{ nullptr, &EVP_MAC_free };
}

class OpenSslCryptoProvider final : public hepatizon::crypto::ICryptoProvider
{
public:
    OpenSslCryptoProvider() : m_argon2idKdf{ fetchArgon2idKdf() }, m_blake2bMac{ fetchBlake2bMac() }
    {
    }

    [[nodiscard]] hepatizon::security::SecureBuffer
    deriveMasterKey(std::span<const std::byte> password, const hepatizon::crypto::KdfMetadata& meta) const override
    {
        if (password.empty())
        {
            throw std::invalid_argument("deriveMasterKey: empty password");
        }
        requirePolicySupported(meta);
        requireArgon2idParamsSafe(meta.argon2id);

        if (!m_argon2idKdf)
        {
            throw std::runtime_error("deriveMasterKey: OpenSSL Argon2id KDF not available");
        }

        EvpKdfCtxPtr ctx{ EVP_KDF_CTX_new(m_argon2idKdf.get()), &EVP_KDF_CTX_free };
        if (!ctx)
        {
            throw std::runtime_error("deriveMasterKey: EVP_KDF_CTX_new failed");
        }

        std::uint32_t iter{ meta.argon2id.iterations };
        std::uint32_t memcostKiB{ meta.argon2id.memoryKiB };
        std::uint32_t lanes{ meta.argon2id.parallelism };
        std::uint32_t threads{ meta.argon2id.parallelism };
        std::uint32_t version{ meta.argon2Version };

        // OpenSSL's OSSL_PARAM API uses non-const pointers even for read-only octet string inputs.
        // To avoid const_cast (and any risk of a provider writing through the pointer), copy inputs to local buffers.
        hepatizon::security::SecureBuffer passwordCopy{};
        passwordCopy.resize(password.size());
        std::memcpy(passwordCopy.data(), password.data(), password.size());

        auto saltCopy{ meta.salt };

        OSSL_PARAM params[]{
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, passwordCopy.data(), passwordCopy.size()),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, saltCopy.data(), saltCopy.size()),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
            OSSL_PARAM_construct_uint32(g_kKdfParamArgon2Memcost, &memcostKiB),
            OSSL_PARAM_construct_uint32(g_kKdfParamArgon2Lanes, &lanes),
            OSSL_PARAM_construct_uint32(g_kKdfParamThreads, &threads),
            OSSL_PARAM_construct_uint32(g_kKdfParamArgon2Version, &version),
            OSSL_PARAM_construct_end(),
        };

        hepatizon::security::SecureBuffer out{};
        out.resize(meta.derivedKeyBytes);
        if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) <= 0)
        {
            throw std::runtime_error("deriveMasterKey: EVP_KDF_derive failed");
        }
        return out;
    }

    [[nodiscard]] hepatizon::security::SecureBuffer deriveSubkey(std::span<const std::uint8_t> masterKey,
                                                                 std::span<const std::byte> context,
                                                                 std::size_t outBytes) const override
    {
        if (masterKey.empty())
        {
            throw std::invalid_argument("deriveSubkey: empty masterKey");
        }
        if (context.empty())
        {
            throw std::invalid_argument("deriveSubkey: empty context");
        }

        if (size_t constexpr maxOutBytes{ 64U }; outBytes == 0U || outBytes > maxOutBytes)
        {
            throw std::invalid_argument("deriveSubkey: invalid outBytes");
        }
        if (!m_blake2bMac)
        {
            throw std::runtime_error("deriveSubkey: OpenSSL BLAKE2BMAC not available");
        }

        EvpMacCtxPtr ctx{ EVP_MAC_CTX_new(m_blake2bMac.get()), &EVP_MAC_CTX_free };
        if (!ctx)
        {
            throw std::runtime_error("deriveSubkey: EVP_MAC_CTX_new failed");
        }

        std::size_t outSize{ outBytes };
        OSSL_PARAM params[]{
            OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outSize),
            OSSL_PARAM_construct_end(),
        };

        if (EVP_MAC_init(ctx.get(), masterKey.data(), masterKey.size(), params) != 1)
        {
            throw std::runtime_error("deriveSubkey: EVP_MAC_init failed");
        }

        const auto* msg{ reinterpret_cast<const unsigned char*>(context.data()) };
        if (EVP_MAC_update(ctx.get(), msg, context.size()) != 1)
        {
            throw std::runtime_error("deriveSubkey: EVP_MAC_update failed");
        }

        hepatizon::security::SecureBuffer out{};
        out.resize(outBytes);
        std::size_t written{ out.size() };
        if (EVP_MAC_final(ctx.get(), out.data(), &written, out.size()) != 1 || written != out.size())
        {
            throw std::runtime_error("deriveSubkey: EVP_MAC_final failed");
        }

        return out;
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
        if (plainText.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::invalid_argument("aeadEncrypt: plainText too large");
        }
        if (associatedData.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::invalid_argument("aeadEncrypt: associatedData too large");
        }

        hepatizon::crypto::AeadBox box{};
        if (!randomBytes(std::span<std::uint8_t>{ box.nonce }))
        {
            throw std::runtime_error("aeadEncrypt: CSPRNG failure");
        }

        EvpCipherCtxPtr ctx{ EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free };
        if (!ctx)
        {
            throw std::runtime_error("aeadEncrypt: EVP_CIPHER_CTX_new failed");
        }

        if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        {
            throw std::runtime_error("aeadEncrypt: EVP_EncryptInit_ex failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(box.nonce.size()), nullptr) != 1)
        {
            throw std::runtime_error("aeadEncrypt: set ivlen failed");
        }
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), box.nonce.data()) != 1)
        {
            throw std::runtime_error("aeadEncrypt: set key/nonce failed");
        }

        int len{ 0 };
        const auto* adPtr{ reinterpret_cast<const unsigned char*>(associatedData.data()) };
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, adPtr, static_cast<int>(associatedData.size())) != 1)
        {
            throw std::runtime_error("aeadEncrypt: add aad failed");
        }

        box.cipherText.resize(plainText.size());
        int outLen{ 0 };
        const auto* ptPtr{ reinterpret_cast<const unsigned char*>(plainText.data()) };
        auto* ctPtr{ box.cipherText.empty() ? nullptr : box.cipherText.data() };
        if (EVP_EncryptUpdate(ctx.get(), ctPtr, &outLen, ptPtr, static_cast<int>(plainText.size())) != 1)
        {
            throw std::runtime_error("aeadEncrypt: encrypt update failed");
        }
        if (outLen < 0 || static_cast<std::size_t>(outLen) > box.cipherText.size())
        {
            throw std::runtime_error("aeadEncrypt: invalid output length");
        }
        int finalLen{ 0 };
        auto* ctFinalPtr{ box.cipherText.empty() ? nullptr : (box.cipherText.data() + outLen) };
        if (EVP_EncryptFinal_ex(ctx.get(), ctFinalPtr, &finalLen) != 1)
        {
            throw std::runtime_error("aeadEncrypt: encrypt final failed");
        }
        if (finalLen < 0)
        {
            throw std::runtime_error("aeadEncrypt: invalid output length");
        }
        const std::size_t totalBytes{ static_cast<std::size_t>(outLen) + static_cast<std::size_t>(finalLen) };
        if (totalBytes > box.cipherText.size())
        {
            throw std::runtime_error("aeadEncrypt: invalid output length");
        }
        box.cipherText.resize(totalBytes);

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(box.tag.size()), box.tag.data()) !=
            1)
        {
            throw std::runtime_error("aeadEncrypt: get tag failed");
        }

        return box;
    }

    [[nodiscard]] std::optional<hepatizon::security::SecureBuffer>
    aeadDecrypt(std::span<const std::uint8_t> key, const hepatizon::crypto::AeadBox& box,
                std::span<const std::byte> associatedData) override
    {
        requireExactSize(key, hepatizon::crypto::g_aeadKeyBytes, "aeadDecrypt: key");
        if (associatedData.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::invalid_argument("aeadDecrypt: associatedData too large");
        }
        if (box.cipherText.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::invalid_argument("aeadDecrypt: cipherText too large");
        }

        EvpCipherCtxPtr ctx{ EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free };
        if (!ctx)
        {
            throw std::runtime_error("aeadDecrypt: EVP_CIPHER_CTX_new failed");
        }

        if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        {
            throw std::runtime_error("aeadDecrypt: EVP_DecryptInit_ex failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(box.nonce.size()), nullptr) != 1)
        {
            throw std::runtime_error("aeadDecrypt: set ivlen failed");
        }
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), box.nonce.data()) != 1)
        {
            throw std::runtime_error("aeadDecrypt: set key/nonce failed");
        }

        int len{ 0 };
        const auto* adPtr{ reinterpret_cast<const unsigned char*>(associatedData.data()) };
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, adPtr, static_cast<int>(associatedData.size())) != 1)
        {
            throw std::runtime_error("aeadDecrypt: add aad failed");
        }

        hepatizon::security::SecureBuffer plainText{};
        plainText.resize(box.cipherText.size());

        int outLen{ 0 };
        const auto* ctPtr{ box.cipherText.empty() ? nullptr : box.cipherText.data() };
        auto* ptPtr{ plainText.empty() ? nullptr : plainText.data() };
        if (EVP_DecryptUpdate(ctx.get(), ptPtr, &outLen, ctPtr, static_cast<int>(box.cipherText.size())) != 1)
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }
        if (outLen < 0 || static_cast<std::size_t>(outLen) > plainText.size())
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }

        std::array<std::uint8_t, hepatizon::crypto::g_aeadTagBytes> tagCopy{ box.tag };
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagCopy.size()), tagCopy.data()) !=
            1)
        {
            throw std::runtime_error("aeadDecrypt: set tag failed");
        }

        int finalLen{ 0 };
        auto* ptFinalPtr{ plainText.empty() ? nullptr : (plainText.data() + outLen) };
        if (EVP_DecryptFinal_ex(ctx.get(), ptFinalPtr, &finalLen) != 1)
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }
        if (finalLen < 0)
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }
        const std::size_t totalBytes{ static_cast<std::size_t>(outLen) + static_cast<std::size_t>(finalLen) };
        if (totalBytes > plainText.size())
        {
            hepatizon::security::secureRelease(plainText);
            return std::nullopt;
        }
        plainText.resize(totalBytes);

        return plainText;
    }

private:
    EvpKdfPtr m_argon2idKdf{ nullptr, &EVP_KDF_free };
    EvpMacPtr m_blake2bMac{ nullptr, &EVP_MAC_free };
};

} // namespace

[[nodiscard]] std::unique_ptr<hepatizon::crypto::ICryptoProvider> makeOpenSslCryptoProvider()
{
    return std::make_unique<OpenSslCryptoProvider>();
}

} // namespace hepatizon::crypto::providers

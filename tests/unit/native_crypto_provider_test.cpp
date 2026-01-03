#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>

#include "hepatizon/crypto/KeyDerivation.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/security/SecureEquals.hpp"

namespace
{

constexpr std::uint32_t g_fastMemoryKiB{ 8U };
constexpr std::uint8_t g_keyByteBase{ 0xA0U };

std::span<const std::byte> asBytes(std::span<const std::uint8_t> s) noexcept
{
    return std::as_bytes(s);
}

std::span<const std::byte> asBytes(std::string_view s) noexcept
{
    return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
}

} // namespace

TEST(NativeCryptoProvider, DeriveMasterKeyMatchesKdfBackend)
{
    auto provider = hepatizon::crypto::providers::makeNativeCryptoProvider();

    hepatizon::crypto::KdfMetadata meta{};
    meta.argon2id =
        hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = g_fastMemoryKiB, .parallelism = 1U };
    meta.salt[0] = 0x01;
    meta.salt[1] = 0x02;

    constexpr std::string_view kPassword{ "strongPassword" };

    const auto a = provider->deriveMasterKey(asBytes(kPassword), meta);
    const auto b = hepatizon::crypto::deriveMasterKeyArgon2id(
        asBytes(kPassword), asBytes(std::span<const std::uint8_t>{ meta.salt }), meta.argon2id);

    ASSERT_EQ(a.size(), hepatizon::crypto::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::crypto::g_kMasterKeyBytes);
    EXPECT_TRUE(hepatizon::security::secureEquals(a, b));
}

TEST(NativeCryptoProvider, AeadRoundTrip)
{
    auto provider = hepatizon::crypto::providers::makeNativeCryptoProvider();

    std::array<std::uint8_t, hepatizon::crypto::g_aeadKeyBytes> key{};
    for (std::size_t i{}; i < key.size(); ++i)
    {
        key[i] = static_cast<std::uint8_t>(i);
    }

    constexpr std::string_view kAd{ "header" };
    constexpr std::string_view kPlain{ "secret-data" };

    const auto box = provider->aeadEncrypt(std::span<const std::uint8_t>{ key }, asBytes(kPlain), asBytes(kAd));
    const auto decrypted = provider->aeadDecrypt(std::span<const std::uint8_t>{ key }, box, asBytes(kAd));

    ASSERT_TRUE(decrypted.has_value());
    const std::string_view decryptedView{ reinterpret_cast<const char*>(decrypted->data()), decrypted->size() };
    EXPECT_EQ(decryptedView, kPlain);
}

TEST(NativeCryptoProvider, AeadTamperFails)
{
    auto provider = hepatizon::crypto::providers::makeNativeCryptoProvider();

    std::array<std::uint8_t, hepatizon::crypto::g_aeadKeyBytes> key{};
    for (std::size_t i{}; i < key.size(); ++i)
    {
        key[i] = static_cast<std::uint8_t>(g_keyByteBase + i);
    }

    constexpr std::string_view kAd{ "header" };
    constexpr std::string_view kPlain{ "secret-data" };

    auto box = provider->aeadEncrypt(std::span<const std::uint8_t>{ key }, asBytes(kPlain), asBytes(kAd));
    box.tag[0] ^= 0x01U;

    const auto decrypted = provider->aeadDecrypt(std::span<const std::uint8_t>{ key }, box, asBytes(kAd));
    EXPECT_FALSE(decrypted.has_value());
}

TEST(NativeCryptoProvider, RejectsWrongKeySize)
{
    auto provider = hepatizon::crypto::providers::makeNativeCryptoProvider();

    std::array<std::uint8_t, hepatizon::crypto::g_aeadKeyBytes - 1U> key{};
    EXPECT_THROW((void)provider->aeadEncrypt(std::span<const std::uint8_t>{ key }, asBytes("x"), asBytes("")),
                 std::invalid_argument);
}

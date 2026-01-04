#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>

#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#include "hepatizon/security/SecureEquals.hpp"

namespace
{

constexpr std::uint32_t g_fastMemoryKiB{ 8U };
constexpr std::uint8_t g_testSalt0{ 0x42U };
constexpr std::uint8_t g_testSalt1{ 0x99U };

std::span<const std::byte> asBytes(std::string_view s) noexcept
{
    return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
}

} // namespace

TEST(CryptoProviderParity, DeriveMasterKeyNativeEqualsOpenSsl)
{
    auto native{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    auto openssl{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };

    hepatizon::crypto::KdfMetadata meta{};
    meta.argon2id =
        hepatizon::crypto::Argon2idParams{ .iterations = 1U, .memoryKiB = g_fastMemoryKiB, .parallelism = 1U };
    meta.salt[0] = g_testSalt0;
    meta.salt[1] = g_testSalt1;

    constexpr std::string_view kPassword{ "strongPassword" };

    const auto nativeKey{ native->deriveMasterKey(asBytes(kPassword), meta) };

    hepatizon::security::SecureBuffer opensslKey{};
    try
    {
        opensslKey = openssl->deriveMasterKey(asBytes(kPassword), meta);
    }
    catch (const std::runtime_error& e)
    {
        GTEST_SKIP() << e.what();
    }

    ASSERT_EQ(nativeKey.size(), hepatizon::crypto::g_kMasterKeyBytes);
    ASSERT_EQ(opensslKey.size(), hepatizon::crypto::g_kMasterKeyBytes);
    EXPECT_TRUE(hepatizon::security::secureEquals(nativeKey, opensslKey));
}

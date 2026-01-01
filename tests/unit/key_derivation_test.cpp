#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <span>
#include <stdexcept>

#include "hepatizon/security/KeyDerivation.hpp"
#include "hepatizon/security/SecureEquals.hpp"

namespace
{

constexpr hepatizon::security::Argon2idParams kFastTestParams{ .iterations = 1U, .memoryKiB = 8U };
constexpr hepatizon::security::Argon2idParams kLargerTestParams{ .iterations = 3U, .memoryKiB = 64U * 1024U };

constexpr std::string_view kStrongPassword{"strongPassword"};

std::span<const std::byte> asBytes(std::string_view s)
{
    return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
}

} // namespace

TEST(KeyDerivation, RejectsEmptyPassword)
{
    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> salt{};
    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(std::span<const std::byte>{}, std::span{ salt }, kFastTestParams),
                 std::invalid_argument);
}

TEST(KeyDerivation, RejectsWrongSaltSize)
{
    std::array<std::byte, 15U> salt{};
    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, kFastTestParams),
                 std::invalid_argument);
}

TEST(KeyDerivation, RejectsUnsafeParameters)
{
    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> salt{};

    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, { .iterations = 0U, .memoryKiB = 8U }),
                 std::invalid_argument);
    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, { .iterations = 1U, .memoryKiB = 7U }),
                 std::invalid_argument);

    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, { .iterations = 11U, .memoryKiB = 8U }),
                 std::invalid_argument);
    EXPECT_THROW((void)hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, { .iterations = 1U, .memoryKiB = 1024U * 1024U + 1U }),
                 std::invalid_argument);
}

TEST(KeyDerivation, Produces32ByteKeyAndIsDeterministic)
{
    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> salt{};
    salt[0] = std::byte{ 0x01 };
    salt[1] = std::byte{ 0x02 };
    salt[2] = std::byte{ 0x03 };

    const auto a = hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, kFastTestParams);
    const auto b = hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, kFastTestParams);

    ASSERT_EQ(a.size(), hepatizon::security::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::security::g_kMasterKeyBytes);
    EXPECT_TRUE(hepatizon::security::secureEquals(a, b));
}

TEST(KeyDerivation, DifferentSaltProducesDifferentKey)
{
    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> saltA{};
    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> saltB{};
    saltA[0] = std::byte{ 0x01 };
    saltB[0] = std::byte{ 0x02 };

    const auto a = hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ saltA }, kFastTestParams);
    const auto b = hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ saltB }, kFastTestParams);

    ASSERT_EQ(a.size(), hepatizon::security::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::security::g_kMasterKeyBytes);
    EXPECT_FALSE(hepatizon::security::secureEquals(a, b));
}

TEST(KeyDerivation, LargerParamsDerives32ByteKey)
{
    if (std::getenv("HEPC_RUN_SLOW_TESTS") == nullptr)
    {
        GTEST_SKIP() << "Set HEPC_RUN_SLOW_TESTS=1 to run slow KDF tests.";
    }

    std::array<std::byte, hepatizon::security::g_argon2SaltBytes> salt{};
    salt[0] = std::byte{ 0x10 };
    salt[1] = std::byte{ 0x20 };
    salt[2] = std::byte{ 0x30 };

    const auto key = hepatizon::security::deriveMasterKeyArgon2id(asBytes(kStrongPassword), std::span{ salt }, kLargerTestParams);
    ASSERT_EQ(key.size(), hepatizon::security::g_kMasterKeyBytes);
}

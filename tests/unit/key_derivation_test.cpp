#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdlib>
#include <span>
#include <stdexcept>

#include "hepatizon/crypto/KeyDerivation.hpp"
#include "hepatizon/security/SecureEquals.hpp"

namespace
{

constexpr std::size_t g_invalidSaltBytes{ hepatizon::crypto::g_argon2SaltBytes - 1U };
constexpr std::byte g_slowSalt0{ std::byte{ 0x10 } };
constexpr std::byte g_slowSalt1{ std::byte{ 0x20 } };
constexpr std::byte g_slowSalt2{ std::byte{ 0x30 } };

constexpr hepatizon::crypto::Argon2idParams g_kFastTestParams{ .iterations = 1U, .memoryKiB = 8U, .parallelism = 1U };
constexpr hepatizon::crypto::Argon2idParams g_kLargerTestParams{ .iterations = 3U,
                                                                 .memoryKiB = 64U * 1024U,
                                                                 .parallelism = 1U };

constexpr std::string_view g_kStrongPassword{ "strongPassword" };

std::span<const std::byte> asBytes(std::string_view s)
{
    return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
}

} // namespace

TEST(KeyDerivation, RejectsEmptyPassword)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    EXPECT_THROW((void)hepatizon::crypto::deriveMasterKeyArgon2id(std::span<const std::byte>{}, std::span{ salt },
                                                                  g_kFastTestParams),
                 std::invalid_argument);
}

TEST(KeyDerivation, RejectsWrongSaltSize)
{
    std::array<std::byte, g_invalidSaltBytes> salt{};
    EXPECT_THROW((void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                                  g_kFastTestParams),
                 std::invalid_argument);
}

TEST(KeyDerivation, RejectsZeroParallelism)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 1U, .memoryKiB = 8U, .parallelism = 0U }),
        std::invalid_argument);
}

TEST(KeyDerivation, RejectsUnsafeParameters)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};

    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 0U, .memoryKiB = 8U, .parallelism = 1U }),
        std::invalid_argument);
    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 1U, .memoryKiB = 7U, .parallelism = 1U }),
        std::invalid_argument);

    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 11U, .memoryKiB = 8U, .parallelism = 1U }),
        std::invalid_argument);
    EXPECT_THROW((void)hepatizon::crypto::deriveMasterKeyArgon2id(
                     asBytes(g_kStrongPassword), std::span{ salt },
                     { .iterations = 1U, .memoryKiB = 1024U * 1024U + 1U, .parallelism = 1U }),
                 std::invalid_argument);
}

TEST(KeyDerivation, RejectsTooSmallMemoryForParallelism)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 1U, .memoryKiB = 8U, .parallelism = 2U }),
        std::invalid_argument);
}

TEST(KeyDerivation, RejectsNonDivisibleMemoryForParallelism)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    EXPECT_THROW(
        (void)hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt },
                                                         { .iterations = 1U, .memoryKiB = 20U, .parallelism = 2U }),
        std::invalid_argument);
}

TEST(KeyDerivation, Produces32ByteKeyAndIsDeterministic)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    salt[0] = std::byte{ 0x01 };
    salt[1] = std::byte{ 0x02 };
    salt[2] = std::byte{ 0x03 };

    const auto a =
        hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt }, g_kFastTestParams);
    const auto b =
        hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt }, g_kFastTestParams);

    ASSERT_EQ(a.size(), hepatizon::crypto::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::crypto::g_kMasterKeyBytes);
    EXPECT_TRUE(hepatizon::security::secureEquals(a, b));
}

TEST(KeyDerivation, DifferentParallelismProducesDifferentKey)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    salt[0] = std::byte{ 0x01 };

    constexpr hepatizon::crypto::Argon2idParams kP1{ .iterations = 1U, .memoryKiB = 16U, .parallelism = 1U };
    constexpr hepatizon::crypto::Argon2idParams kP2{ .iterations = 1U, .memoryKiB = 16U, .parallelism = 2U };

    const auto a = hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt }, kP1);
    const auto b = hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt }, kP2);

    ASSERT_EQ(a.size(), hepatizon::crypto::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::crypto::g_kMasterKeyBytes);
    EXPECT_FALSE(hepatizon::security::secureEquals(a, b));
}

TEST(KeyDerivation, DifferentSaltProducesDifferentKey)
{
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> saltA{};
    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> saltB{};
    saltA[0] = std::byte{ 0x01 };
    saltB[0] = std::byte{ 0x02 };

    const auto a =
        hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ saltA }, g_kFastTestParams);
    const auto b =
        hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ saltB }, g_kFastTestParams);

    ASSERT_EQ(a.size(), hepatizon::crypto::g_kMasterKeyBytes);
    ASSERT_EQ(b.size(), hepatizon::crypto::g_kMasterKeyBytes);
    EXPECT_FALSE(hepatizon::security::secureEquals(a, b));
}

TEST(KeyDerivation, LargerParamsDerives32ByteKey)
{
    if (std::getenv("HEPC_RUN_SLOW_TESTS") == nullptr)
    {
        GTEST_SKIP() << "Set HEPC_RUN_SLOW_TESTS=1 to run slow KDF tests.";
    }

    std::array<std::byte, hepatizon::crypto::g_argon2SaltBytes> salt{};
    salt[0] = g_slowSalt0;
    salt[1] = g_slowSalt1;
    salt[2] = g_slowSalt2;

    const auto key =
        hepatizon::crypto::deriveMasterKeyArgon2id(asBytes(g_kStrongPassword), std::span{ salt }, g_kLargerTestParams);
    ASSERT_EQ(key.size(), hepatizon::crypto::g_kMasterKeyBytes);
}

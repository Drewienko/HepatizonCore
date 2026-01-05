#include "hepatizon/security/SecureRandom.hpp"
#include <array>
#include <gtest/gtest.h>

TEST(SecureRandom, FillEmptyIsNoOp)
{
    std::array<std::uint8_t, 0> bytes{};
    EXPECT_TRUE(hepatizon::security::secureRandomFill(std::span{ bytes }));
}

TEST(SecureRandom, FillNonEmptyReturnsTrue)
{
    constexpr std::size_t kBytesLen{ 32U };
    std::array<std::uint8_t, kBytesLen> bytes{};
    EXPECT_TRUE(hepatizon::security::secureRandomFill(std::span{ bytes }));
}

TEST(SecureRandom, Uint64ReturnsTrue)
{
    std::uint64_t value{};
    EXPECT_TRUE(hepatizon::security::secureRandomUint64(value));
}

TEST(SecureRandom, BoundedRejectsZero)
{
    std::uint64_t out{};
    EXPECT_FALSE(hepatizon::security::secureRandomBounded(0U, out));
}

TEST(SecureRandom, BoundedOneAlwaysReturnsZero)
{
    constexpr std::uint64_t kSentinel{ 123U };
    std::uint64_t out{ kSentinel };
    EXPECT_TRUE(hepatizon::security::secureRandomBounded(1U, out));
    EXPECT_EQ(out, 0U);
}

TEST(SecureRandom, BoundedValueIsWithinRange)
{
    std::uint64_t out{};
    constexpr std::uint64_t kMaxExcl{ 10U };
    constexpr int kTrials{ 16 };
    for (int i{}; i < kTrials; ++i)
    {
        ASSERT_TRUE(hepatizon::security::secureRandomBounded(kMaxExcl, out));
        EXPECT_LT(out, kMaxExcl);
    }
}

TEST(SecureRandom, BoundedTemplateOverloadWorksForUint32)
{
    std::uint32_t out{};
    constexpr std::uint32_t kMaxExcl{ 10U };
    ASSERT_TRUE(hepatizon::security::secureRandomBounded(kMaxExcl, out));
    EXPECT_LT(out, kMaxExcl);
}

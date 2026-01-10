#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureEquals.hpp"
#include "hepatizon/security/SecureRandom.hpp"
#include "hepatizon/security/SecureString.hpp"
#include <cstddef>
#include <gtest/gtest.h>
#include <vector>

namespace
{

using namespace hepatizon::security;

TEST(SecureEqualsTest, MismatchedSizesReturnFalse)
{
    std::vector<std::byte> a(10);
    std::vector<std::byte> b(5);
    EXPECT_FALSE(secureEquals(std::span{ a }, std::span{ b }));
}

TEST(SecureEqualsTest, SameSizeDifferentContentReturnsFalse)
{
    std::vector<std::byte> a(10, std::byte{ 1 });
    std::vector<std::byte> b(10, std::byte{ 2 });
    EXPECT_FALSE(secureEquals(std::span{ a }, std::span{ b }));
}

TEST(SecureEqualsTest, SameSizeSameContentReturnsTrue)
{
    std::vector<std::byte> a(10, std::byte{ 1 });
    std::vector<std::byte> b(10, std::byte{ 1 });
    EXPECT_TRUE(secureEquals(std::span{ a }, std::span{ b }));
}

TEST(SecureEqualsTest, OverloadsWork)
{
    SecureBuffer sb1(5);
    SecureBuffer sb2(5);
    EXPECT_TRUE(secureEquals(sb1, sb2));

    auto ss1 = secureStringFrom("abc");
    auto ss2 = secureStringFrom("abc");
    auto ss3 = secureStringFrom("def");
    EXPECT_TRUE(secureEquals(ss1, ss2));
    EXPECT_FALSE(secureEquals(ss1, ss3));
}

TEST(SecureRandomTest, FillEmptySpanSucceeds)
{
    std::span<std::uint8_t> s{};
    EXPECT_TRUE(secureRandomFill(s));
}

TEST(SecureRandomTest, BoundedZeroFails)
{
    std::uint64_t out64{};
    EXPECT_FALSE(secureRandomBounded(0ULL, out64));

    std::uint32_t out32{};
    EXPECT_FALSE(secureRandomBounded(0U, out32));
}

TEST(SecureRandomTest, BoundedOneReturnsZero)
{
    std::uint64_t out64{ 55 };
    EXPECT_TRUE(secureRandomBounded(1ULL, out64));
    EXPECT_EQ(out64, 0ULL);

    std::uint32_t out32{ 55 };
    EXPECT_TRUE(secureRandomBounded(1U, out32));
    EXPECT_EQ(out32, 0U);
}

} // namespace
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>

#include "hepatizon/security/SecureBuffer.hpp"

TEST(SecureBuffer, AsSpanReflectsBuffer)
{
    constexpr std::size_t elementCount{ 4U };
    constexpr std::uint8_t byte0{ 0x11U };
    constexpr std::uint8_t byte1{ 0x22U };
    constexpr std::uint8_t byte2{ 0x33U };
    constexpr std::uint8_t byte3{ 0x44U };

    hepatizon::security::SecureBuffer buffer{};
    buffer.resize(elementCount);
    buffer[0] = byte0;
    buffer[1] = byte1;
    buffer[2] = byte2;
    buffer[3] = byte3;

    const std::span<const std::uint8_t> span{ hepatizon::security::asSpan(buffer) };
    ASSERT_EQ(span.size(), buffer.size());
    EXPECT_EQ(span[0], buffer[0]);
    EXPECT_EQ(span[1], buffer[1]);
    EXPECT_EQ(span[2], buffer[2]);
    EXPECT_EQ(span[3], buffer[3]);
}

TEST(SecureBuffer, SecureWipeSizeZerosContentsAndPreservesSize)
{
    constexpr std::size_t bufferSize{ 64U };
    constexpr std::uint8_t nonZeroByte{ 0xA5U };

    hepatizon::security::SecureBuffer buffer{};
    buffer.resize(bufferSize);
    for (auto& b : buffer)
    {
        b = nonZeroByte;
    }

    const std::size_t oldSize = buffer.size();
    hepatizon::security::secureWipeSize(buffer);

    EXPECT_EQ(buffer.size(), oldSize);
    for (const auto b : buffer)
    {
        EXPECT_EQ(b, std::uint8_t{});
    }
}

TEST(SecureBuffer, SecureResizeShrinksAndPreservesPrefix)
{
    constexpr std::size_t initialSize{ 32U };
    constexpr std::size_t newSize{ 8U };
    constexpr std::uint8_t firstValue{ 1U };

    hepatizon::security::SecureBuffer buffer{};
    buffer.resize(initialSize);
    std::uint8_t value{ firstValue };
    for (auto& b : buffer)
    {
        b = value;
        ++value;
    }

    hepatizon::security::secureResize(buffer, newSize);

    ASSERT_EQ(buffer.size(), newSize);
    std::uint8_t expected{ firstValue };
    for (const auto b : buffer)
    {
        EXPECT_EQ(b, expected);
        ++expected;
    }
}

TEST(SecureBuffer, SecureClearEmptiesAndKeepsCapacity)
{
    constexpr std::size_t reservedCapacity{ 128U };
    constexpr std::size_t bufferSize{ 64U };

    hepatizon::security::SecureBuffer buffer{};
    buffer.reserve(reservedCapacity);
    buffer.resize(bufferSize);

    const std::size_t oldCapacity = buffer.capacity();
    hepatizon::security::secureClear(buffer);

    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.capacity(), oldCapacity);
}

TEST(SecureBuffer, SecureReleaseEmptiesAndDropsCapacity)
{
    constexpr std::size_t reservedCapacity{ 128U };
    constexpr std::size_t bufferSize{ 64U };
    constexpr std::size_t emptyCapacity{};

    hepatizon::security::SecureBuffer buffer{};
    buffer.reserve(reservedCapacity);
    buffer.resize(bufferSize);

    hepatizon::security::secureRelease(buffer);

    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.capacity(), emptyCapacity);
}

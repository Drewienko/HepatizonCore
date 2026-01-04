#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "hepatizon/security/MemoryWiper.hpp"

namespace
{

struct NonTrivial
{
public:
    NonTrivial() = default;
    ~NonTrivial() = default;

private:
    std::unique_ptr<int> m_p;
};

template <typename T>
concept CanSecureWipe = requires(T buffer) { hepatizon::security::secureWipe(buffer); };

static_assert(!CanSecureWipe<std::span<const std::uint32_t>>);
static_assert(!CanSecureWipe<std::span<NonTrivial>>);

} // namespace

TEST(MemoryWiper, ZerosByteSpan)
{
    constexpr std::size_t byteCount{ 64U };
    constexpr std::byte nonZeroByte{ std::byte{ 0xA5 } };

    std::array<std::byte, byteCount> bytes{};
    bytes.fill(nonZeroByte);

    hepatizon::security::secureWipe(std::span{ bytes });

    for (const auto b : bytes)
    {
        EXPECT_EQ(b, std::byte{});
    }
}

TEST(MemoryWiper, ZerosTypedSpanViaTemplate)
{
    constexpr std::size_t wordCount{ 16U };
    constexpr std::uint32_t nonZeroWord{ 0xDEADBEEFU };

    std::array<std::uint32_t, wordCount> words{};
    words.fill(nonZeroWord);

    const std::span<std::uint32_t> wordsSpan{ words };
    hepatizon::security::secureWipe(wordsSpan);

    for (const auto b : std::as_bytes(wordsSpan))
    {
        EXPECT_EQ(b, std::byte{});
    }
}

TEST(MemoryWiper, EmptySpanIsNoOp)
{
    hepatizon::security::secureWipe(std::span<std::byte>{});
}

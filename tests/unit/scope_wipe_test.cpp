#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

#include "hepatizon/security/ScopeWipe.hpp"

namespace
{

constexpr std::size_t bufferSize{32U};
constexpr std::uint8_t nonZeroByte{0xA5U};

void expectAllBytesEq(const std::array<std::uint8_t, bufferSize>& buffer, std::uint8_t expected)
{
    for (const auto b : buffer)
    {
        EXPECT_EQ(b, expected);
    }
}

} // namespace

TEST(ScopeWipe, WipesOnDestruction)
{
    std::array<std::uint8_t, bufferSize> buffer{};
    buffer.fill(nonZeroByte);

    {
        const auto guard = hepatizon::security::scopeWipe(std::span{buffer});
        (void)guard;
        expectAllBytesEq(buffer, nonZeroByte);
    }

    expectAllBytesEq(buffer, std::uint8_t{});
}

TEST(ScopeWipe, ReleaseDisablesWipe)
{
    std::array<std::uint8_t, bufferSize> buffer{};
    buffer.fill(nonZeroByte);

    {
        auto guard = hepatizon::security::scopeWipe(std::span{buffer});
        guard.release();
    }

    expectAllBytesEq(buffer, nonZeroByte);
}

TEST(ScopeWipe, MoveTransfersWipeResponsibility)
{
    std::array<std::uint8_t, bufferSize> buffer{};
    buffer.fill(nonZeroByte);

    {
        auto a = hepatizon::security::scopeWipe(std::span{buffer});
        auto b = std::move(a);
        (void)b;
    }

    expectAllBytesEq(buffer, std::uint8_t{});
}

TEST(ScopeWipe, MoveAssignmentWipesOldThenTakesOver)
{
    std::array<std::uint8_t, bufferSize> first{};
    std::array<std::uint8_t, bufferSize> second{};
    first.fill(nonZeroByte);
    second.fill(nonZeroByte);

    {
        auto guardA = hepatizon::security::scopeWipe(std::span{first});
        auto guardB = hepatizon::security::scopeWipe(std::span{second});

        guardA = std::move(guardB);

        expectAllBytesEq(first, std::uint8_t{});
        expectAllBytesEq(second, nonZeroByte);
    }

    expectAllBytesEq(second, std::uint8_t{});
}


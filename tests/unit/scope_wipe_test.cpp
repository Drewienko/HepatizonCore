#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

#include "hepatizon/security/ScopeWipe.hpp"

namespace
{

constexpr std::size_t g_bufferSize{ 32U };
constexpr std::uint8_t g_nonZeroByte{ 0xA5U };

void expectAllBytesEq(const std::array<std::uint8_t, g_bufferSize>& buffer, std::uint8_t expected)
{
    for (const auto b : buffer)
    {
        EXPECT_EQ(b, expected);
    }
}

} // namespace

TEST(ScopeWipe, WipesOnDestruction)
{
    std::array<std::uint8_t, g_bufferSize> buffer{};
    buffer.fill(g_nonZeroByte);

    {
        const auto guard = hepatizon::security::scopeWipe(std::span{ buffer });
        (void)guard;
        expectAllBytesEq(buffer, g_nonZeroByte);
    }

    expectAllBytesEq(buffer, std::uint8_t{});
}

TEST(ScopeWipe, ReleaseDisablesWipe)
{
    std::array<std::uint8_t, g_bufferSize> buffer{};
    buffer.fill(g_nonZeroByte);

    {
        auto guard = hepatizon::security::scopeWipe(std::span{ buffer });
        guard.release();
    }

    expectAllBytesEq(buffer, g_nonZeroByte);
}

TEST(ScopeWipe, MoveTransfersWipeResponsibility)
{
    std::array<std::uint8_t, g_bufferSize> buffer{};
    buffer.fill(g_nonZeroByte);

    {
        auto a = hepatizon::security::scopeWipe(std::span{ buffer });
        auto b = std::move(a);
        (void)b;
    }

    expectAllBytesEq(buffer, std::uint8_t{});
}

TEST(ScopeWipe, MoveAssignmentWipesOldThenTakesOver)
{
    std::array<std::uint8_t, g_bufferSize> first{};
    std::array<std::uint8_t, g_bufferSize> second{};
    first.fill(g_nonZeroByte);
    second.fill(g_nonZeroByte);

    {
        auto guardA = hepatizon::security::scopeWipe(std::span{ first });
        auto guardB = hepatizon::security::scopeWipe(std::span{ second });

        guardA = std::move(guardB);

        expectAllBytesEq(first, std::uint8_t{});
        expectAllBytesEq(second, g_nonZeroByte);
    }

    expectAllBytesEq(second, std::uint8_t{});
}

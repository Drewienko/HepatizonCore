#include "hepatizon/core/Session.hpp"

#include <gtest/gtest.h>

namespace
{
using hepatizon::core::Session;
using TimePoint = Session::TimePoint;
using Duration = Session::Duration;
} // namespace

TEST(Session, NotExpiredImmediately)
{
    TimePoint now{};
    auto provider = [&]() { return now; };

    hepatizon::core::UnlockedVault vault{};
    Session session{ std::move(vault), Duration{ 5 }, provider };

    EXPECT_FALSE(session.isExpired());
}

TEST(Session, ExpiresAfterTimeout)
{
    TimePoint now{};
    auto provider = [&]() { return now; };

    hepatizon::core::UnlockedVault vault{};
    Session session{ std::move(vault), Duration{ 5 }, provider };

    now += Duration{ 6 };
    EXPECT_TRUE(session.isExpired());
}

TEST(Session, TouchResetsTimer)
{
    TimePoint now{};
    auto provider = [&]() { return now; };

    hepatizon::core::UnlockedVault vault{};
    Session session{ std::move(vault), Duration{ 5 }, provider };

    now += Duration{ 3 };
    session.touch();

    now += Duration{ 4 };
    EXPECT_FALSE(session.isExpired());

    now += Duration{ 2 };
    EXPECT_TRUE(session.isExpired());
}

TEST(Session, ZeroTimeoutDisablesExpiration)
{
    TimePoint now{};
    auto provider = [&]() { return now; };

    hepatizon::core::UnlockedVault vault{};
    Session session{ std::move(vault), Duration{ 0 }, provider };

    now += Duration{ 999 };
    EXPECT_FALSE(session.isExpired());
}

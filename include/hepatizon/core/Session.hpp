#ifndef INCLUDE_HEPATIZON_CORE_SESSION_HPP
#define INCLUDE_HEPATIZON_CORE_SESSION_HPP

#include "hepatizon/core/VaultService.hpp"
#include <chrono>
#include <functional>

namespace hepatizon::core
{

class Session final
{
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = std::chrono::seconds;
    using NowProvider = std::function<TimePoint()>;

    Session(UnlockedVault&& vault, Duration timeout, NowProvider nowProvider = Clock::now);

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) noexcept = default;
    Session& operator=(Session&&) noexcept = default;
    ~Session() = default;

    void touch() noexcept;
    [[nodiscard]] bool isExpired() const noexcept;

    [[nodiscard]] Duration timeout() const noexcept;
    [[nodiscard]] const UnlockedVault& vault() const noexcept;
    [[nodiscard]] UnlockedVault& vault() noexcept;

private:
    NowProvider m_now;
    Duration m_timeout{};
    TimePoint m_lastActivity{};
    UnlockedVault m_vault;
};

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_SESSION_HPP

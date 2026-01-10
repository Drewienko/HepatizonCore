#include "hepatizon/core/Session.hpp"

namespace hepatizon::core
{

Session::Session(UnlockedVault&& vault, Duration timeout, NowProvider nowProvider)
    : m_now(std::move(nowProvider)), m_timeout(timeout), m_lastActivity{}, m_vault(std::move(vault))
{
    m_lastActivity = m_now();
}

void Session::touch() noexcept
{
    m_lastActivity = m_now();
}

bool Session::isExpired() const noexcept
{
    if (m_timeout.count() <= 0)
    {
        return false;
    }

    return (m_now() - m_lastActivity) > m_timeout;
}

Session::Duration Session::timeout() const noexcept
{
    return m_timeout;
}

const UnlockedVault& Session::vault() const noexcept
{
    return m_vault;
}

UnlockedVault& Session::vault() noexcept
{
    return m_vault;
}

} // namespace hepatizon::core

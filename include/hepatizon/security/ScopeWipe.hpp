#ifndef INCLUDE_HEPATIZON_SECURITY_SCOPEWIPE_HPP
#define INCLUDE_HEPATIZON_SECURITY_SCOPEWIPE_HPP

#include "hepatizon/security/MemoryWiper.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureString.hpp"
#include <cstdint>
#include <span>

namespace hepatizon::security
{
class [[nodiscard]] ScopeWipe final
{
public:
    ScopeWipe(const ScopeWipe&) = delete;
    ScopeWipe& operator=(const ScopeWipe&) = delete;

    explicit ScopeWipe(std::span<std::byte> b) noexcept : m_bytes{ b }
    {
    }

    ScopeWipe(ScopeWipe&& sw) noexcept : m_bytes{ sw.m_bytes }, m_active{ sw.m_active }
    {
        sw.release();
    }

    ~ScopeWipe() noexcept
    {
        if (!m_active || m_bytes.empty())
        {
            return;
        }
        secureWipe(m_bytes);
    }

    ScopeWipe& operator=(ScopeWipe&& sw) noexcept
    {
        if (this == &sw)
        {
            return *this;
        }

        if (m_active && !m_bytes.empty())
        {
            secureWipe(m_bytes);
        }

        m_bytes = sw.m_bytes;
        m_active = sw.m_active;
        sw.release();
        return *this;
    }

    void release() noexcept
    {
        m_active = false;
        m_bytes = {};
    }

private:
    std::span<std::byte> m_bytes;
    bool m_active{ true };
};

[[nodiscard]] inline ScopeWipe scopeWipe(std::span<std::byte> b) noexcept
{
    return ScopeWipe{ b };
}

[[nodiscard]] inline ScopeWipe scopeWipe(std::span<std::uint8_t> b) noexcept
{
    return ScopeWipe{ std::as_writable_bytes(b) };
}

[[nodiscard]] inline ScopeWipe scopeWipe(SecureBuffer& b) noexcept
{
    return ScopeWipe{ asWritableBytes(b) };
}

[[nodiscard]] inline ScopeWipe scopeWipe(SecureString& s) noexcept
{
    return ScopeWipe{ asWritableBytes(s) };
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_SCOPEWIPE_HPP

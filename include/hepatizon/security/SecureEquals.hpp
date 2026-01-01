#ifndef INCLUDE_HEPATIZON_SECURITY_SECUREEQUALS_HPP
#define INCLUDE_HEPATIZON_SECURITY_SECUREEQUALS_HPP

#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/SecureString.hpp"
#include <cstddef>
#include <cstdint>
#include <span>

namespace hepatizon::security
{
[[nodiscard]] inline bool secureEquals(std::span<const std::byte> a, std::span<const std::byte> b) noexcept
{
    if (a.size() != b.size())
    {
        return false;
    }

    volatile unsigned char diff{};

    for (std::size_t i{}; i < a.size(); ++i)
    {
        const unsigned char x{ std::to_integer<unsigned char>(a[i]) };
        const unsigned char y{ std::to_integer<unsigned char>(b[i]) };

        diff |= (x ^ y);
    }

    return (diff == 0);
}

[[nodiscard]] inline bool secureEquals(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) noexcept
{
    return secureEquals(std::as_bytes(a), std::as_bytes(b));
}

[[nodiscard]] inline bool secureEquals(const SecureBuffer& a, const SecureBuffer& b) noexcept
{
    return secureEquals(asBytes(a), asBytes(b));
}

[[nodiscard]] inline bool secureEquals(const SecureString& a, const SecureString& b) noexcept
{
    return secureEquals(asBytes(a), asBytes(b));
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_SECUREEQUALS_HPP
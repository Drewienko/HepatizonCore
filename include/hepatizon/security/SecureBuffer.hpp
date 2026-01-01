#ifndef INCLUDE_HEPATIZON_SECURITY_SECUREBUFFER_HPP
#define INCLUDE_HEPATIZON_SECURITY_SECUREBUFFER_HPP

#include "hepatizon/security/ZeroAllocator.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace hepatizon::security
{
using SecureBuffer = std::vector<std::uint8_t, ZeroAllocator<std::uint8_t>>;

[[nodiscard]] inline std::span<std::uint8_t> asSpan(SecureBuffer& b) noexcept
{
    return std::span{ b };
}

[[nodiscard]] inline std::span<const std::uint8_t> asSpan(const SecureBuffer& b) noexcept
{
    return std::span{ b };
}

[[nodiscard]] inline std::span<std::byte> asWritableBytes(SecureBuffer& b) noexcept
{
    return std::as_writable_bytes(std::span{ b });
}

[[nodiscard]] inline std::span<const std::byte> asBytes(const SecureBuffer& b) noexcept
{
    return std::as_bytes(std::span{ b });
}

inline void secureWipeSize(SecureBuffer& b) noexcept
{
    secureWipe(asWritableBytes(b));
}

inline void secureResize(SecureBuffer& b, std::size_t newSize)
{
    if (newSize < b.size())
    {
        auto full = asSpan(b);
        secureWipe(std::as_writable_bytes(full.subspan(newSize)));
    }
    b.resize(newSize);
}

inline void secureClear(SecureBuffer& b) noexcept
{
    secureWipeSize(b);
    b.clear();
}

inline void secureRelease(SecureBuffer& b) noexcept
{
    secureWipeSize(b);
    SecureBuffer temp;
    b.swap(temp);
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_SECUREBUFFER_HPP
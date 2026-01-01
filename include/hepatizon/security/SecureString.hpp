#ifndef INCLUDE_HEPATIZON_SECURITY_SECURESTRING_HPP
#define INCLUDE_HEPATIZON_SECURITY_SECURESTRING_HPP

#include "hepatizon/security/SecureBuffer.hpp"
#include "hepatizon/security/ZeroAllocator.hpp"
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace hepatizon::security
{
using SecureString = std::vector<char, ZeroAllocator<char>>;

[[nodiscard]] inline SecureString secureStringFrom(std::string_view s)
{
    // Use parentheses to strictly enforce the Range Constructor.
    // NOLINTNEXTLINE(modernize-return-braced-init-list)
    return SecureString(s.begin(), s.end());
}

[[nodiscard]] inline std::span<char> asSpan(SecureString& s) noexcept
{
    return std::span{ s };
}

[[nodiscard]] inline std::span<const char> asSpan(const SecureString& s) noexcept
{
    return std::span{ s };
}

[[nodiscard]] inline std::string_view asStringView(const SecureString& s) noexcept
{
    if (s.empty())
    {
        return {};
    }
    return std::string_view{ s.data(), s.size() };
}

[[nodiscard]] inline std::span<std::byte> asWritableBytes(SecureString& s) noexcept
{
    return std::as_writable_bytes(std::span{ s });
}

[[nodiscard]] inline std::span<const std::byte> asBytes(const SecureString& s) noexcept
{
    return std::as_bytes(std::span{ s });
}

[[nodiscard]] inline SecureBuffer toSecureBuffer(const SecureString& s)
{
    SecureBuffer buf{};
    buf.reserve(s.size());
    for (char c : s)
    {
        buf.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
    }
    return buf;
}

inline void secureWipeSize(SecureString& s) noexcept
{
    secureWipe(asWritableBytes(s));
}

inline void secureResize(SecureString& s, std::size_t newSize)
{
    if (newSize < s.size())
    {
        auto fullSpan = asWritableBytes(s);
        secureWipe(fullSpan.subspan(newSize));
    }
    s.resize(newSize);
}

inline void secureClear(SecureString& s) noexcept
{
    secureWipeSize(s);
    s.clear();
}

inline void secureRelease(SecureString& s) noexcept
{
    secureWipeSize(s);
    SecureString temp{};
    s.swap(temp);
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_SECURESTRING_HPP
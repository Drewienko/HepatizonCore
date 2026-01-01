#ifndef INCLUDE_HEPATIZON_SECURITY_MEMORYWIPER_HPP
#define INCLUDE_HEPATIZON_SECURITY_MEMORYWIPER_HPP

#include <cstddef>
#include <span>
#include <type_traits>

namespace hepatizon::security
{
void secureWipe(std::span<std::byte> bytes) noexcept;

template <typename T>
    requires(!std::is_const_v<T> && std::is_trivially_copyable_v<T>)
void secureWipe(std::span<T> buffer) noexcept
{
    secureWipe(std::as_writable_bytes(buffer));
}
} // namespace hepatizon::security
#endif // INCLUDE_HEPATIZON_SECURITY_MEMORYWIPER_HPP
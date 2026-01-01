#ifndef INCLUDE_HEPATIZON_SECURITY_SECURERANDOM_HPP
#define INCLUDE_HEPATIZON_SECURITY_SECURERANDOM_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace hepatizon::security
{

[[nodiscard]] bool secureRandomFill(std::span<std::uint8_t> out) noexcept;
[[nodiscard]] bool secureRandomUint64(std::uint64_t& out) noexcept;
[[nodiscard]] bool secureRandomBounded(std::uint64_t maxExcl, std::uint64_t& out) noexcept;

template <std::unsigned_integral T>
    requires(!std::same_as<T, std::uint64_t>)
[[nodiscard]] bool secureRandomBounded(T maxExcl, T& out) noexcept
{
    if (maxExcl == 0U)
    {
        return false;
    }

    if constexpr (sizeof(T) > sizeof(std::uint64_t))
    {
        const T uint64MaxAsT{ static_cast<T>(std::numeric_limits<std::uint64_t>::max()) };
        if (maxExcl > uint64MaxAsT)
        {
            return false;
        }
    }

    std::uint64_t result{};
    if (!secureRandomBounded(static_cast<std::uint64_t>(maxExcl), result))
    {
        return false;
    }

    if constexpr (sizeof(T) < sizeof(std::uint64_t))
    {
        const std::uint64_t tMax{ static_cast<std::uint64_t>(std::numeric_limits<T>::max()) };
        if (result > tMax)
        {
            return false;
        }
    }

    out = static_cast<T>(result);
    return true;
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_SECURERANDOM_HPP

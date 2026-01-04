#include "hepatizon/security/SecureRandom.hpp"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <limits>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#else
#error Unsupported platform
#endif

namespace hepatizon::security
{
bool secureRandomFill(std::span<std::uint8_t> out) noexcept
{
    if (out.empty())
    {
        return true;
    }
    std::uint8_t* outPtr{ out.data() };
    std::size_t remaining{ out.size() };
#if defined(_WIN32)

    constexpr std::size_t kMaxChunk{ static_cast<std::size_t>(std::numeric_limits<ULONG>::max()) };
    while (remaining > 0U)
    {
        const std::size_t chunk{ (remaining > kMaxChunk) ? kMaxChunk : remaining };

        const NTSTATUS status{ BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(outPtr), static_cast<ULONG>(chunk),
                                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if (!BCRYPT_SUCCESS(status))
        {
            return false;
        }

        remaining -= chunk;
        outPtr += chunk;
    }

#elif defined(__linux__)
    while (remaining > 0)
    {
        const ssize_t bytesReceived{ ::getrandom(outPtr, remaining, 0) };

        if (bytesReceived > 0)
        {
            const std::size_t received{ static_cast<std::size_t>(bytesReceived) };
            if (received > remaining)
            {
                return false;
            }
            remaining -= received;
            outPtr += received;
            continue;
        }

        if (bytesReceived == 0)
        {
            return false;
        }

        if (errno == EINTR)
        {
            continue;
        }

        return false;
    }

#endif
    return true;
}

bool secureRandomUint64(std::uint64_t& out) noexcept
{
    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    if (!secureRandomFill(std::span{ bytes }))
    {
        return false;
    }

    std::uint64_t value{};
    std::memcpy(&value, bytes.data(), sizeof(value));
    out = value;
    return true;
}

bool secureRandomBounded(std::uint64_t maxExcl, std::uint64_t& out) noexcept
{
    if (maxExcl == 0U)
    {
        return false;
    }
    if (maxExcl == 1U)
    {
        out = 0U;
        return true;
    }

    const std::uint64_t limit{ (std::numeric_limits<std::uint64_t>::max() / maxExcl) * maxExcl };

    constexpr std::size_t kMaxAttempts{ 128U };
    for (std::size_t attempt{}; attempt < kMaxAttempts; ++attempt)
    {
        std::uint64_t candidate{};
        if (!secureRandomUint64(candidate))
        {
            return false;
        }

        if (candidate < limit)
        {
            out = candidate % maxExcl;
            return true;
        }
    }
    return false;
}

} // namespace hepatizon::security

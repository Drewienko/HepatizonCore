#include "hepatizon/security/MemoryWiper.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#elif defined(__linux__)
#include <string.h>
#else
#error Unsupported platform
#endif

namespace hepatizon::security
{
void secureWipe(std::span<std::byte> bytes) noexcept
{
    if (bytes.empty())
    {
        return;
    }
#if defined(_WIN32)
    ::SecureZeroMemory(bytes.data(), bytes.size());
#elif defined(__linux__)
    ::explicit_bzero(bytes.data(), bytes.size());
#endif
}
} // namespace hepatizon::security

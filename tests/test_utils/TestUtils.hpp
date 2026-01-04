#ifndef HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP
#define HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP

#include "hepatizon/security/SecureRandom.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace hepatizon::test_utils
{

[[nodiscard]] inline std::string toHex(std::span<const std::uint8_t> bytes)
{
    constexpr char kHex[] = "0123456789abcdef";
    constexpr std::uint8_t kNibbleShift{ 4U };
    constexpr std::uint8_t kNibbleMask{ 0x0FU };

    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const std::uint8_t b : bytes)
    {
        out.push_back(kHex[(b >> kNibbleShift) & kNibbleMask]);
        out.push_back(kHex[b & kNibbleMask]);
    }
    return out;
}

// Creates a unique directory inside the OS temp dir using OS CSPRNG.
// The name is intentionally non-predictable to avoid security-sensitive patterns in publicly writable temp folders.
[[nodiscard]] inline std::filesystem::path makeSecureTempDir(std::string_view prefix)
{
    constexpr std::size_t kTokenBytes{ 16U };
    constexpr std::size_t kMaxAttempts{ 16U };

    const auto base = std::filesystem::temp_directory_path() / std::filesystem::path{ "hepatizoncore_tests" };
    std::error_code ec{};
    (void)std::filesystem::create_directories(base, ec);

    for (std::size_t attempt{}; attempt < kMaxAttempts; ++attempt)
    {
        std::array<std::uint8_t, kTokenBytes> rnd{};
        if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ rnd }))
        {
            break;
        }

        std::string name{ prefix };
        name += toHex(std::span<const std::uint8_t>{ rnd });
        const auto dir = base / std::filesystem::path{ name };
        if (std::filesystem::create_directory(dir, ec) && !ec)
        {
            return dir;
        }
    }

    return {};
}

} // namespace hepatizon::test_utils

#endif // HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP


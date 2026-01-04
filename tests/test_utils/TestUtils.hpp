#ifndef HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP
#define HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP

#include "hepatizon/security/SecureRandom.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace hepatizon::test_utils
{

[[nodiscard]] inline std::optional<std::string> getEnv(std::string_view name);

namespace detail
{

[[nodiscard]] inline std::filesystem::path xdgRuntimeRoot() noexcept
{
    std::filesystem::path root{};
    if (const auto xdgRuntimeDir{ getEnv("XDG_RUNTIME_DIR") }; xdgRuntimeDir.has_value() && !xdgRuntimeDir->empty())
    {
        root = std::filesystem::path{ *xdgRuntimeDir };
    }
    return root;
}

[[nodiscard]] inline bool tryPrepareBaseDir(const std::filesystem::path& candidate) noexcept
{
    std::error_code ec{};

#if !defined(_WIN32)
    ec.clear();
    const bool existed{ std::filesystem::exists(candidate, ec) };
    if (ec)
    {
        return false;
    }
    if (!existed)
    {
        ec.clear();
        if (!std::filesystem::create_directories(candidate, ec) || ec)
        {
            return false;
        }
    }

    ec.clear();
    if (!std::filesystem::is_directory(candidate, ec) || ec)
    {
        return false;
    }

    // Ensure the base dir isn't usable if we can't make it private.
    ec.clear();
    std::filesystem::permissions(candidate, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace,
                                 ec);
    if (ec)
    {
        return false;
    }

    ec.clear();
    const auto perms{ std::filesystem::status(candidate, ec).permissions() };
    if (ec)
    {
        return false;
    }
    const auto publicBits{ std::filesystem::perms::group_all | std::filesystem::perms::others_all };
    return ((perms & publicBits) == std::filesystem::perms::none);
#else
    ec.clear();
    if (!std::filesystem::create_directories(candidate, ec) && ec)
    {
        return false;
    }
    ec.clear();
    return std::filesystem::is_directory(candidate, ec) && !ec;
#endif
}

[[nodiscard]] inline bool tryHardenNewDir(const std::filesystem::path& dir) noexcept
{
#if defined(_WIN32)
    (void)dir;
    return true;
#else
    std::error_code ec{};
    ec.clear();
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
    return !ec;
#endif
}

} // namespace detail

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

[[nodiscard]] inline std::optional<std::string> getEnv(std::string_view name)
{
    if (name.empty())
    {
        return std::nullopt;
    }

#if defined(_WIN32)
    // Use MSVC "secure" getenv replacement to avoid C4996 when /WX is enabled.
    char* value{ nullptr };
    std::size_t len{ 0U };
    if (_dupenv_s(&value, &len, std::string{ name }.c_str()) != 0 || value == nullptr)
    {
        return std::nullopt;
    }
    std::string out{ value };
    std::free(value);
    return out;
#else
    const char* value{ std::getenv(std::string{ name }.c_str()) };
    if (value == nullptr)
    {
        return std::nullopt;
    }
    return std::string{ value };
#endif
}

[[nodiscard]] inline bool envFlagSet(std::string_view name)
{
    const auto value{ getEnv(name) };
    if (!value.has_value())
    {
        return false;
    }

    // Treat any non-empty value other than "0" as enabled.
    return !value->empty() && (*value != "0");
}

// Creates a unique directory inside the OS temp dir using OS CSPRNG.
// The name is intentionally non-predictable to avoid security-sensitive patterns in publicly writable temp folders.
[[nodiscard]] inline std::filesystem::path makeSecureTempDir(std::string_view prefix)
{
    constexpr std::size_t kTokenBytes{ 16U };
    constexpr std::size_t kMaxAttempts{ 16U };

    std::filesystem::path base{};
    {
        const std::filesystem::path tmpRoot{ std::filesystem::temp_directory_path() };
        const std::array<std::filesystem::path, 2> roots{ detail::xdgRuntimeRoot(), tmpRoot };
        for (const auto& root : roots)
        {
            if (root.empty())
            {
                continue;
            }

            const auto candidate{ root / std::filesystem::path{ "hepatizoncore_tests" } };
            if (!detail::tryPrepareBaseDir(candidate))
            {
                continue;
            }

            base = candidate;
            break;
        }
    }
    if (base.empty())
    {
        return {};
    }

    for (std::size_t attempt{}; attempt < kMaxAttempts; ++attempt)
    {
        std::array<std::uint8_t, kTokenBytes> rnd{};
        if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ rnd }))
        {
            break;
        }

        std::string name{ prefix };
        name += toHex(std::span<const std::uint8_t>{ rnd });
        const auto dir{ base / std::filesystem::path{ name } };

        std::error_code ec{};
        if (std::filesystem::create_directory(dir, ec) && !ec)
        {
            if (!detail::tryHardenNewDir(dir))
            {
                ec.clear();
                std::filesystem::remove_all(dir, ec);
                continue;
            }
            return dir;
        }
    }

    return {};
}

} // namespace hepatizon::test_utils

#endif // HEPATIZON_TESTS_TEST_UTILS_TESTUTILS_HPP

#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/security/SecureRandom.hpp"
#include <span>

namespace hepatizon::core
{

[[nodiscard]] hepatizon::crypto::Argon2idParams defaultArgon2idParams() noexcept
{
    constexpr std::uint32_t kDefaultIterations{ 3U };
    constexpr std::uint32_t kDefaultMemoryMiB{ 64U };
    constexpr std::uint32_t kKiBPerMiB{ 1024U };
    constexpr std::uint32_t kDefaultParallelism{ 1U };

    return hepatizon::crypto::Argon2idParams{
        .iterations = kDefaultIterations,
        .memoryKiB = kDefaultMemoryMiB * kKiBPerMiB,
        .parallelism = kDefaultParallelism,
    };
}

[[nodiscard]] std::optional<hepatizon::crypto::KdfMetadata>
makeKdfMetadata(hepatizon::crypto::Argon2idParams params) noexcept
{
    hepatizon::crypto::KdfMetadata meta{};
    meta.argon2id = params;

    if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ meta.salt }))
    {
        return std::nullopt;
    }

    return meta;
}

[[nodiscard]] std::optional<hepatizon::crypto::KdfMetadata> makeDefaultKdfMetadata() noexcept
{
    return makeKdfMetadata(defaultArgon2idParams());
}

} // namespace hepatizon::core

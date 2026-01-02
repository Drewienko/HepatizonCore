#ifndef INCLUDE_HEPATIZON_CRYPTO_KDFMETADATA_HPP
#define INCLUDE_HEPATIZON_CRYPTO_KDFMETADATA_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace hepatizon::crypto
{

constexpr std::size_t g_argon2SaltBytes{ 16 };
constexpr std::size_t g_kMasterKeyBytes{ 32 };

constexpr std::uint32_t g_kKdfPolicyVersion{ 1 };

// Argon2 version v1.3 (0x13). Monocypher is hardcoded to this.
constexpr std::uint32_t g_kArgon2VersionV13{ 0x13 };

enum class KdfAlgorithm : std::uint32_t
{
    Argon2id = 1U,
};

struct Argon2idParams final
{
    std::uint32_t iterations;
    std::uint32_t memoryKiB;
    std::uint32_t parallelism;
};

struct KdfMetadata final
{
    std::uint32_t policyVersion{ g_kKdfPolicyVersion };
    KdfAlgorithm algorithm{ KdfAlgorithm::Argon2id };
    std::uint32_t argon2Version{ g_kArgon2VersionV13 };
    std::uint32_t derivedKeyBytes{ static_cast<std::uint32_t>(g_kMasterKeyBytes) };

    Argon2idParams argon2id{};
    std::array<std::uint8_t, g_argon2SaltBytes> salt{};
};

} // namespace hepatizon::crypto

#endif // INCLUDE_HEPATIZON_CRYPTO_KDFMETADATA_HPP

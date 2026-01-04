#include "hepatizon/core/VaultHeaderAad.hpp"

#include "LittleEndian.hpp"
#include <cstddef>
#include <span>

namespace hepatizon::core
{
namespace
{

constexpr std::array<std::byte, g_vaultHeaderAadPrefixBytes> g_kAadPrefix{
    static_cast<std::byte>('H'), static_cast<std::byte>('E'), static_cast<std::byte>('P'), static_cast<std::byte>('C'),
    static_cast<std::byte>('H'), static_cast<std::byte>('D'), static_cast<std::byte>('R'), static_cast<std::byte>('1'),
};

constexpr std::size_t g_kU32Bytes{ hepatizon::core::detail::g_kU32Bytes };

void writeSalt(std::span<std::byte, hepatizon::crypto::g_argon2SaltBytes> out,
               const std::array<std::uint8_t, hepatizon::crypto::g_argon2SaltBytes>& salt) noexcept
{
    for (std::size_t i{}; i < salt.size(); ++i)
    {
        out[i] = static_cast<std::byte>(salt[i]);
    }
}

} // namespace

[[nodiscard]] std::array<std::byte, g_vaultHeaderAadV1Bytes>
encodeVaultHeaderAadV1(const hepatizon::crypto::KdfMetadata& meta) noexcept
{
    std::array<std::byte, g_vaultHeaderAadV1Bytes> out{};

    std::size_t offset{};
    for (std::size_t i{}; i < g_kAadPrefix.size(); ++i)
    {
        out[i] = g_kAadPrefix[i];
    }
    offset += g_kAadPrefix.size();

    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.policyVersion);
    offset += g_kU32Bytes;
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        static_cast<std::uint32_t>(meta.algorithm));
    offset += g_kU32Bytes;
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.argon2Version);
    offset += g_kU32Bytes;
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.derivedKeyBytes);
    offset += g_kU32Bytes;

    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.argon2id.iterations);
    offset += g_kU32Bytes;
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.argon2id.memoryKiB);
    offset += g_kU32Bytes;
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        meta.argon2id.parallelism);
    offset += g_kU32Bytes;

    writeSalt(std::span<std::byte, hepatizon::crypto::g_argon2SaltBytes>{ out.data() + offset,
                                                                          hepatizon::crypto::g_argon2SaltBytes },
              meta.salt);

    return out;
}

} // namespace hepatizon::core

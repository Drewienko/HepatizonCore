#include "hepatizon/core/VaultHeader.hpp"

#include "LittleEndian.hpp"
#include <cstddef>

namespace hepatizon::core
{
namespace
{

constexpr std::size_t g_kU32Bytes{ hepatizon::core::detail::g_kU32Bytes };
constexpr std::size_t g_kU64Bytes{ hepatizon::core::detail::g_kU64Bytes };

} // namespace

[[nodiscard]] std::array<std::byte, g_vaultHeaderV1Bytes> encodeVaultHeaderV1(const VaultHeaderV1& header) noexcept
{
    std::array<std::byte, g_vaultHeaderV1Bytes> out{};

    std::size_t offset{};
    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        header.headerVersion);
    offset += g_kU32Bytes;

    for (std::size_t i{}; i < header.vaultId.size(); ++i)
    {
        out[offset + i] = static_cast<std::byte>(header.vaultId[i]);
    }
    offset += header.vaultId.size();

    hepatizon::core::detail::writeU64LE(std::span<std::byte, g_kU64Bytes>{ out.data() + offset, g_kU64Bytes },
                                        header.createdAtUnixSeconds);
    offset += g_kU64Bytes;

    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        header.dbSchemaVersion);
    offset += g_kU32Bytes;

    hepatizon::core::detail::writeU32LE(std::span<std::byte, g_kU32Bytes>{ out.data() + offset, g_kU32Bytes },
                                        header.flags);

    return out;
}

[[nodiscard]] std::optional<VaultHeaderV1> decodeVaultHeaderV1(std::span<const std::byte> bytes) noexcept
{
    if (bytes.size() != g_vaultHeaderV1Bytes)
    {
        return std::nullopt;
    }

    VaultHeaderV1 header{};

    std::size_t offset{};
    header.headerVersion = hepatizon::core::detail::readU32LE(
        std::span<const std::byte, g_kU32Bytes>{ bytes.data() + offset, g_kU32Bytes });
    offset += g_kU32Bytes;
    if (header.headerVersion != g_vaultHeaderVersionV1)
    {
        return std::nullopt;
    }

    for (std::size_t i{}; i < header.vaultId.size(); ++i)
    {
        header.vaultId[i] = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(bytes[offset + i]));
    }
    offset += header.vaultId.size();

    header.createdAtUnixSeconds = hepatizon::core::detail::readU64LE(
        std::span<const std::byte, g_kU64Bytes>{ bytes.data() + offset, g_kU64Bytes });
    offset += g_kU64Bytes;

    header.dbSchemaVersion = hepatizon::core::detail::readU32LE(
        std::span<const std::byte, g_kU32Bytes>{ bytes.data() + offset, g_kU32Bytes });
    offset += g_kU32Bytes;

    header.flags = hepatizon::core::detail::readU32LE(
        std::span<const std::byte, g_kU32Bytes>{ bytes.data() + offset, g_kU32Bytes });

    return header;
}

} // namespace hepatizon::core

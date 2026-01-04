#ifndef INCLUDE_HEPATIZON_CORE_VAULTHEADER_HPP
#define INCLUDE_HEPATIZON_CORE_VAULTHEADER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace hepatizon::core
{

constexpr std::uint32_t g_vaultHeaderVersionV1{ 1U };
constexpr std::size_t g_vaultIdBytes{ 16U };
constexpr std::uint32_t g_vaultDbSchemaVersionV0{ 0U };
constexpr std::uint32_t g_vaultDbSchemaVersionV1{ 1U };
constexpr std::uint32_t g_vaultDbSchemaVersionCurrent{ g_vaultDbSchemaVersionV1 };

struct VaultHeaderV1 final
{
    std::uint32_t headerVersion{ g_vaultHeaderVersionV1 };
    std::array<std::uint8_t, g_vaultIdBytes> vaultId{};
    std::uint64_t createdAtUnixSeconds{ 0U };
    std::uint32_t dbSchemaVersion{ g_vaultDbSchemaVersionCurrent };
    std::uint32_t flags{ 0U };
};

constexpr std::size_t g_vaultHeaderV1Bytes{ 4U + g_vaultIdBytes + 8U + 4U + 4U };

[[nodiscard]] std::array<std::byte, g_vaultHeaderV1Bytes> encodeVaultHeaderV1(const VaultHeaderV1& header) noexcept;

[[nodiscard]] std::optional<VaultHeaderV1> decodeVaultHeaderV1(std::span<const std::byte> bytes) noexcept;

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_VAULTHEADER_HPP

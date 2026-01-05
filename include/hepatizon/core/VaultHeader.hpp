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
constexpr std::uint32_t g_vaultHeaderVersionV2{ 2U };
constexpr std::uint32_t g_vaultHeaderVersionCurrent{ g_vaultHeaderVersionV2 };

constexpr std::size_t g_vaultIdBytes{ 16U };
constexpr std::uint32_t g_vaultDbSchemaVersionV0{ 0U };
constexpr std::uint32_t g_vaultDbSchemaVersionV1{ 1U };
constexpr std::uint32_t g_vaultDbSchemaVersionCurrent{ g_vaultDbSchemaVersionV1 };

struct VaultHeader final
{
    std::uint32_t headerVersion{ g_vaultHeaderVersionCurrent };
    std::array<std::uint8_t, g_vaultIdBytes> vaultId{};
    std::uint64_t createdAtUnixSeconds{ 0U };
    std::uint32_t dbSchemaVersion{ g_vaultDbSchemaVersionCurrent };
    std::uint32_t flags{ 0U };
};

constexpr std::size_t g_vaultHeaderV1Bytes{ 4U + g_vaultIdBytes + 8U + 4U + 4U };
constexpr std::size_t g_vaultSecretsKeyBytes{ 32U };
constexpr std::size_t g_vaultHeaderV2Bytes{ g_vaultHeaderV1Bytes + g_vaultSecretsKeyBytes };

// V1 payload: header only (no stored secrets key). Kept for compatibility with early vaults/tests.
[[nodiscard]] std::array<std::byte, g_vaultHeaderV1Bytes> encodeVaultHeaderV1(const VaultHeader& header) noexcept;

[[nodiscard]] std::optional<VaultHeader> decodeVaultHeaderV1(std::span<const std::byte> bytes) noexcept;

// V2 payload: header + stored secrets key ("DEK") appended.
[[nodiscard]] std::array<std::byte, g_vaultHeaderV2Bytes>
encodeVaultHeaderV2(const VaultHeader& header, std::span<const std::uint8_t> secretsKey) noexcept;

// Decodes a V2 payload into a header and an out-parameter secrets key.
[[nodiscard]] bool decodeVaultHeaderV2(std::span<const std::byte> bytes, VaultHeader& outHeader,
                                      std::span<std::uint8_t> outSecretsKey) noexcept;

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_VAULTHEADER_HPP

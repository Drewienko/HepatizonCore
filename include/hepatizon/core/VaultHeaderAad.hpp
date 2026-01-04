#ifndef INCLUDE_HEPATIZON_CORE_VAULTHEADERAAD_HPP
#define INCLUDE_HEPATIZON_CORE_VAULTHEADERAAD_HPP

#include "hepatizon/crypto/KdfMetadata.hpp"
#include <array>
#include <cstddef>

namespace hepatizon::core
{

constexpr std::size_t g_kdfMetadataAadBytes{ 4U + 4U + 4U + 4U + 4U + 4U + 4U + hepatizon::crypto::g_argon2SaltBytes };
constexpr std::size_t g_vaultHeaderAadPrefixBytes{ 8U };
constexpr std::size_t g_vaultHeaderAadV1Bytes{ g_vaultHeaderAadPrefixBytes + g_kdfMetadataAadBytes };

[[nodiscard]] std::array<std::byte, g_vaultHeaderAadV1Bytes>
encodeVaultHeaderAadV1(const hepatizon::crypto::KdfMetadata& meta) noexcept;

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_VAULTHEADERAAD_HPP

#ifndef INCLUDE_HEPATIZON_SECURITY_KEYDERIVATION_HPP
#define INCLUDE_HEPATIZON_SECURITY_KEYDERIVATION_HPP

#include "hepatizon/security/SecureBuffer.hpp"
#include <cstddef>
#include <cstdint>
#include <span>

namespace hepatizon::security
{
constexpr std::size_t g_argon2SaltBytes{ 16 };
constexpr std::size_t g_kMasterKeyBytes{ 32 };
constexpr std::uint32_t g_kArgon2idPolicyVersion{ 1 };

struct Argon2idParams final
{
    std::uint32_t iterations;
    std::uint32_t memoryKiB;
};
constexpr Argon2idParams g_kArgon2idDefaultParams{ .iterations = 3, .memoryKiB = 64U * 1024U };

[[nodiscard]] SecureBuffer deriveMasterKeyArgon2id(std::span<const std::byte> password, std::span<const std::byte> salt,
                                                   Argon2idParams params);

[[nodiscard]] SecureBuffer deriveMasterKeyArgon2idDefault(std::span<const std::byte> password,
                                                          std::span<const std::byte> salt);
} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_KEYDERIVATION_HPP
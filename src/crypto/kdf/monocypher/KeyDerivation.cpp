#include "hepatizon/crypto/KeyDerivation.hpp"

#include "hepatizon/security/ZeroAllocator.hpp"
#include "monocypher.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace hepatizon::crypto
{

[[nodiscard]] hepatizon::security::SecureBuffer deriveMasterKeyArgon2id(std::span<const std::byte> password,
                                                                       std::span<const std::byte> salt,
                                                                       Argon2idParams params)
{
    if (password.empty())
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: empty password");
    }
    if (salt.size() != g_argon2SaltBytes)
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: invalid salt size");
    }
    if (params.iterations == 0U || params.memoryKiB < 8U)
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: invalid parameters");
    }

    constexpr std::uint32_t memoryKiBCap{ 1024U * 1024U };
    constexpr std::uint32_t iterationsCap{ 10U };
    if (params.memoryKiB > memoryKiBCap || params.iterations > iterationsCap)
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: unsafe parameters");
    }

    if (password.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: password too large");
    }
    if (salt.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: salt too large");
    }

    const std::uint32_t passSize{ static_cast<std::uint32_t>(password.size()) };
    const std::uint32_t saltSize{ static_cast<std::uint32_t>(salt.size()) };

    constexpr std::size_t kU64WordsPerKiB{ 128U }; // 1024 / sizeof(uint64_t)
    if (params.memoryKiB > (std::numeric_limits<std::size_t>::max() / kU64WordsPerKiB))
    {
        throw std::bad_alloc{};
    }
    const std::size_t workWords{ static_cast<std::size_t>(params.memoryKiB) * kU64WordsPerKiB };
    std::vector<std::uint64_t, hepatizon::security::ZeroAllocator<std::uint64_t>> workArea(workWords);

    hepatizon::security::SecureBuffer masterKey;
    masterKey.resize(g_kMasterKeyBytes);
    if (masterKey.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("deriveMasterKeyArgon2id: invalid output size");
    }

    const auto* passPtr{ reinterpret_cast<const std::uint8_t*>(password.data()) };
    const auto* saltPtr{ reinterpret_cast<const std::uint8_t*>(salt.data()) };

    const crypto_argon2_config cfg{
        .algorithm = CRYPTO_ARGON2_ID, .nb_blocks = params.memoryKiB, .nb_passes = params.iterations, .nb_lanes = 1U
    };

    const crypto_argon2_inputs inputs{ .pass = passPtr, .salt = saltPtr, .pass_size = passSize, .salt_size = saltSize };

    crypto_argon2(masterKey.data(), static_cast<std::uint32_t>(masterKey.size()), workArea.data(), cfg, inputs,
                  crypto_argon2_no_extras);

    return masterKey;
}

[[nodiscard]] hepatizon::security::SecureBuffer deriveMasterKeyArgon2idDefault(std::span<const std::byte> password,
                                                                              std::span<const std::byte> salt)
{
    return deriveMasterKeyArgon2id(password, salt, g_kArgon2idDefaultParams);
}

} // namespace hepatizon::crypto

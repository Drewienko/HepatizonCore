#ifndef INCLUDE_HEPATIZON_CRYPTO_KEYDERIVATION_HPP
#define INCLUDE_HEPATIZON_CRYPTO_KEYDERIVATION_HPP

#include "hepatizon/crypto/KdfMetadata.hpp"
#include "hepatizon/security/SecureBuffer.hpp"
#include <span>

namespace hepatizon::crypto
{

[[nodiscard]] hepatizon::security::SecureBuffer
deriveMasterKeyArgon2id(std::span<const std::byte> password, std::span<const std::byte> salt, Argon2idParams params);

} // namespace hepatizon::crypto

#endif // INCLUDE_HEPATIZON_CRYPTO_KEYDERIVATION_HPP


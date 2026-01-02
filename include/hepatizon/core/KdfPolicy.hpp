#ifndef INCLUDE_HEPATIZON_CORE_KDFPOLICY_HPP
#define INCLUDE_HEPATIZON_CORE_KDFPOLICY_HPP

#include "hepatizon/crypto/KdfMetadata.hpp"
#include <optional>

namespace hepatizon::core
{

[[nodiscard]] hepatizon::crypto::Argon2idParams defaultArgon2idParams() noexcept;

[[nodiscard]] std::optional<hepatizon::crypto::KdfMetadata> makeDefaultKdfMetadata() noexcept;

} // namespace hepatizon::core

#endif // INCLUDE_HEPATIZON_CORE_KDFPOLICY_HPP

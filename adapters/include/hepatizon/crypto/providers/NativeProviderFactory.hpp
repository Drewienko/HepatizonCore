#ifndef INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_NATIVEPROVIDERFACTORY_HPP
#define INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_NATIVEPROVIDERFACTORY_HPP

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include <memory>

namespace hepatizon::crypto::providers
{

[[nodiscard]] std::unique_ptr<hepatizon::crypto::ICryptoProvider> makeNativeCryptoProvider();

} // namespace hepatizon::crypto::providers

#endif // INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_NATIVEPROVIDERFACTORY_HPP

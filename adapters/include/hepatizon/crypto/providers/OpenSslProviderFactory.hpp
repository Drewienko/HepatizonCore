#ifndef INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_OPENSSLPROVIDERFACTORY_HPP
#define INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_OPENSSLPROVIDERFACTORY_HPP

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include <memory>

namespace hepatizon::crypto::providers
{

[[nodiscard]] std::unique_ptr<hepatizon::crypto::ICryptoProvider> makeOpenSslCryptoProvider();

} // namespace hepatizon::crypto::providers

#endif // INCLUDE_HEPATIZON_CRYPTO_PROVIDERS_OPENSSLPROVIDERFACTORY_HPP


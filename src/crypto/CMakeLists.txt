add_library(hepatizon_crypto_native STATIC
    native/native_anchor.cpp
)

target_link_libraries(hepatizon_crypto_native
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
    PRIVATE
        hepatizon_vendor_monocypher
)

hepc_set_common_warnings(hepatizon_crypto_native)

add_library(hepatizon_crypto_openssl STATIC
    openssl/openssl_anchor.cpp
)

target_link_libraries(hepatizon_crypto_openssl
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
        OpenSSL::SSL
        OpenSSL::Crypto
)

hepc_set_common_warnings(hepatizon_crypto_openssl)

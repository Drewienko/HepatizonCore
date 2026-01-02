add_library(hepatizon_kdf_monocypher STATIC
    kdf/monocypher/KeyDerivation.cpp
)

target_link_libraries(hepatizon_kdf_monocypher
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
    PRIVATE
        hepatizon_vendor_monocypher
)

hepc_set_common_warnings(hepatizon_kdf_monocypher)

add_library(hepatizon_crypto_native STATIC
    native/native_anchor.cpp
    native/NativeCryptoProvider.cpp
)

target_link_libraries(hepatizon_crypto_native
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
    PRIVATE
        hepatizon_kdf_monocypher
        hepatizon_vendor_monocypher
)

hepc_set_common_warnings(hepatizon_crypto_native)

if(HEPC_ENABLE_OPENSSL)
    add_library(hepatizon_crypto_openssl STATIC
        openssl/openssl_anchor.cpp
        openssl/OpenSslCryptoProvider.cpp
    )

    target_link_libraries(hepatizon_crypto_openssl
        PUBLIC
            hepatizon_interfaces
            hepatizon_security
            OpenSSL::SSL
            OpenSSL::Crypto
    )

    hepc_set_common_warnings(hepatizon_crypto_openssl)
endif()

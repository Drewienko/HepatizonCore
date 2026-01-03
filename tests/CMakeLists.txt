find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

if(GTest_FOUND)
    add_executable(hepatizoncore_tests
        unit/sample_test.cpp
        unit/memory_wiper_test.cpp
        unit/secure_buffer_test.cpp
        unit/secure_string_test.cpp
        unit/scope_wipe_test.cpp
        unit/key_derivation_test.cpp
        unit/native_crypto_provider_test.cpp
    )
    target_link_libraries(hepatizoncore_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        hepatizon_adapters_headers
        hepatizon_security
        hepatizon_kdf_monocypher
        hepatizon_crypto_native
    )
    hepc_set_common_warnings(hepatizoncore_tests)
    add_test(NAME hepatizoncore_tests COMMAND hepatizoncore_tests)

    if(HEPC_ENABLE_OPENSSL)
        target_sources(hepatizoncore_tests PRIVATE
            unit/openssl_kdf_parity_test.cpp
        )
        target_link_libraries(hepatizoncore_tests PRIVATE
            hepatizon_crypto_openssl
        )
    endif()
else()
    message(STATUS "GTest not found; skipping tests target.")
endif()

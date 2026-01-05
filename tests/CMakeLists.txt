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
        unit/secure_random_test.cpp
        unit/key_derivation_test.cpp
        unit/native_crypto_provider_test.cpp
        unit/sqlite_storage_repository_test.cpp
        unit/vault_service_error_test.cpp
        unit/vault_service_native_integration_test.cpp
    )
    target_include_directories(hepatizoncore_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(hepatizoncore_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        hepatizon_adapters_headers
        hepatizon_security
        hepatizon_core
        hepatizon_kdf_monocypher
        hepatizon_crypto_native
        hepatizon_storage_sqlite
    )
    hepc_set_common_warnings(hepatizoncore_tests)
    add_test(NAME hepatizoncore_tests COMMAND hepatizoncore_tests)

    if(HEPC_ENABLE_OPENSSL)
        target_sources(hepatizoncore_tests PRIVATE
            unit/openssl_kdf_parity_test.cpp
            unit/vault_service_openssl_integration_test.cpp
        )
        target_link_libraries(hepatizoncore_tests PRIVATE
            hepatizon_crypto_openssl
        )
    endif()
else()
    message(STATUS "GTest not found; skipping tests target.")
endif()

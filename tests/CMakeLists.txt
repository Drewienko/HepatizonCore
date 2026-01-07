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
        unit/tokenizer_test.cpp
        unit/console_utils_test.cpp
        unit/zero_allocator_test.cpp
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

    if(HEPC_BUILD_CLI)
        find_package(CLI11 CONFIG REQUIRED)
        
        target_sources(hepatizoncore_tests PRIVATE
            unit/interactive_shell_test.cpp
            ../src/ui/cli/InteractiveShell.cpp
            ../src/ui/cli/Tokenizer.cpp
            ../src/ui/cli/ConsoleUtils.cpp
        )

        target_include_directories(hepatizoncore_tests PRIVATE
            ../src/ui/cli
        )

        target_link_libraries(hepatizoncore_tests PRIVATE
            CLI11::CLI11
        )
    endif()

    if(HEPC_ENABLE_OPENSSL)
        target_sources(hepatizoncore_tests PRIVATE
            unit/openssl_kdf_parity_test.cpp
            unit/vault_service_openssl_integration_test.cpp
        )
        target_link_libraries(hepatizoncore_tests PRIVATE
            hepatizon_crypto_openssl
        )
        target_compile_definitions(hepatizoncore_tests PRIVATE HEPC_ENABLE_OPENSSL=1)
    endif()

    if(HEPC_BUILD_GUI)
        find_package(Qt6 COMPONENTS Widgets Test REQUIRED)

        add_executable(hepatizon_gui_tests
            gui/main.cpp
            gui/TestLoginView.cpp
            ../src/ui/gui/views/LoginView.cpp
        )

        target_include_directories(hepatizon_gui_tests PRIVATE
            gui
            ../src/ui/gui
            ../include
            ../adapters/include
        )

        target_link_libraries(hepatizon_gui_tests PRIVATE
            GTest::gtest
            Qt6::Widgets
            Qt6::Test
            hepatizon_core
            hepatizon_crypto_native
            hepatizon_storage_sqlite
            hepatizon_security
        )

        set_target_properties(hepatizon_gui_tests PROPERTIES 
            AUTOMOC ON
            CXX_STANDARD 20
        )

        add_test(NAME hepatizon_gui_tests COMMAND hepatizon_gui_tests)
        hepc_set_common_warnings(hepatizon_gui_tests)
    endif()
else()
    message(STATUS "GTest not found; skipping tests target.")
endif()
if(HEPC_BUILD_CLI)
    find_package(CLI11 CONFIG REQUIRED)

    add_executable(hepatizoncore_cli
        cli/main.cpp
        cli/ConsoleUtils.cpp
        cli/InteractiveShell.cpp
        cli/Tokenizer.cpp
    )

    # Allow headers inside cli/ to be included comfortably
    target_include_directories(hepatizoncore_cli PRIVATE cli)

    target_link_libraries(hepatizoncore_cli PRIVATE
        hepatizon_core
        hepatizon_adapters_headers
        hepatizon_crypto_native
        hepatizon_storage_sqlite
        CLI11::CLI11
    )

    if(HEPC_ENABLE_OPENSSL)
        target_link_libraries(hepatizoncore_cli PRIVATE hepatizon_crypto_openssl)
        # Critical: Pass the definition to the C++ code
        target_compile_definitions(hepatizoncore_cli PRIVATE HEPC_ENABLE_OPENSSL=1)
    endif()

    hepc_set_common_warnings(hepatizoncore_cli)
endif()

if(HEPC_BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets REQUIRED)

    add_executable(hepatizoncore_gui
        gui/main.cpp
    )
    target_link_libraries(hepatizoncore_gui PRIVATE hepatizon_core Qt6::Widgets)
    set_target_properties(hepatizoncore_gui PROPERTIES
        WIN32_EXECUTABLE TRUE
        MACOSX_BUNDLE TRUE
    )
    hepc_set_common_warnings(hepatizoncore_gui)
endif()
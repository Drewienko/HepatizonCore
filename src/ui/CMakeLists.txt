if(HEPC_BUILD_CLI)
    find_package(CLI11 CONFIG REQUIRED)

    add_executable(hepatizoncore_cli
        cli/main.cpp
        cli/ConsoleUtils.cpp
        cli/InteractiveShell.cpp
        cli/Tokenizer.cpp
    )

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

        target_compile_definitions(hepatizoncore_cli PRIVATE HEPC_ENABLE_OPENSSL=1)
    endif()

    hepc_set_common_warnings(hepatizoncore_cli)
endif()

if(HEPC_BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets REQUIRED)

    set(CMAKE_AUTOMOC ON)

    set(CMAKE_AUTORCC ON)

    set(CMAKE_AUTOUIC OFF)

    add_executable(hepatizoncore_gui
        gui/main.cpp
        gui/MainWindow.cpp
        gui/MainWindow.hpp            
        gui/components/TitleBar.cpp
        gui/components/TitleBar.hpp
        gui/components/SecretDialog.cpp
        gui/components/SecretDialog.hpp
        gui/components/SettingsDialog.cpp
        gui/components/SettingsDialog.hpp
        gui/GuiSettings.hpp
        gui/views/LoginView.cpp
        gui/views/LoginView.hpp
        gui/views/DashboardView.cpp
        gui/views/DashboardView.hpp    
        gui/views/AddSecretView.cpp
        gui/views/AddSecretView.hpp
        resources.qrc
    )
    
    target_include_directories(hepatizoncore_gui PRIVATE gui)


    target_link_libraries(hepatizoncore_gui PRIVATE 
        hepatizon_core 
        Qt6::Widgets
        hepatizon_adapters_headers
        hepatizon_crypto_native
        hepatizon_storage_sqlite
    )

    set_target_properties(hepatizoncore_gui PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
    
    hepc_set_common_warnings(hepatizoncore_gui)
endif()

if(HEPC_BUILD_CLI)
    add_executable(hepatizoncore_cli
        cli/main.cpp
    )
    target_link_libraries(hepatizoncore_cli PRIVATE hepatizon_core)
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

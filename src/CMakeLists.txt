add_library(hepatizoncore_core INTERFACE)
target_include_directories(hepatizoncore_core
    INTERFACE
        "${PROJECT_SOURCE_DIR}/include"
)
target_compile_features(hepatizoncore_core INTERFACE cxx_std_20)

if(HEPC_BUILD_CLI)
    add_executable(hepatizoncore_cli
        ui/cli/main.cpp
    )
    target_link_libraries(hepatizoncore_cli PRIVATE hepatizoncore_core)
    hepc_set_common_warnings(hepatizoncore_cli)
endif()

if(HEPC_BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets REQUIRED)

    add_executable(hepatizoncore_gui
        ui/gui/main.cpp
    )
    target_link_libraries(hepatizoncore_gui PRIVATE hepatizoncore_core Qt6::Widgets)
    set_target_properties(hepatizoncore_gui PROPERTIES
        WIN32_EXECUTABLE TRUE
        MACOSX_BUNDLE TRUE
    )
    hepc_set_common_warnings(hepatizoncore_gui)
endif()

add_library(onyxcitadel_core INTERFACE)
target_include_directories(onyxcitadel_core
    INTERFACE
        "${PROJECT_SOURCE_DIR}/include"
)
target_compile_features(onyxcitadel_core INTERFACE cxx_std_20)

if(ONYC_BUILD_CLI)
    add_executable(onyxcitadel_cli
        ui/cli/main.cpp
    )
    target_link_libraries(onyxcitadel_cli PRIVATE onyxcitadel_core)
    onyc_set_common_warnings(onyxcitadel_cli)
endif()

if(ONYC_BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets REQUIRED)

    add_executable(onyxcitadel_gui
        ui/gui/main.cpp
    )
    target_link_libraries(onyxcitadel_gui PRIVATE onyxcitadel_core Qt6::Widgets)
    set_target_properties(onyxcitadel_gui PROPERTIES
        WIN32_EXECUTABLE TRUE
        MACOSX_BUNDLE TRUE
    )
    onyc_set_common_warnings(onyxcitadel_gui)
endif()

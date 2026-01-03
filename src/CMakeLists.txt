add_library(hepatizon_interfaces INTERFACE)
target_include_directories(hepatizon_interfaces
    INTERFACE
        "${PROJECT_SOURCE_DIR}/include"
)
target_compile_features(hepatizon_interfaces INTERFACE cxx_std_20)

add_library(hepatizon_adapters_headers INTERFACE)
target_include_directories(hepatizon_adapters_headers
    INTERFACE
        "${PROJECT_SOURCE_DIR}/adapters/include"
)
target_compile_features(hepatizon_adapters_headers INTERFACE cxx_std_20)

add_subdirectory(security)
add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(platform)
add_subdirectory(ui)

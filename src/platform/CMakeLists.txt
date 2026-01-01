add_library(hepatizon_platform STATIC
    platform_anchor.cpp
)

target_link_libraries(hepatizon_platform
    PUBLIC
        hepatizon_interfaces
)

hepc_set_common_warnings(hepatizon_platform)

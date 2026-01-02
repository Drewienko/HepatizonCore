add_library(hepatizon_core STATIC
    core_anchor.cpp
    KdfPolicy.cpp
)

target_link_libraries(hepatizon_core
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
)

hepc_set_common_warnings(hepatizon_core)

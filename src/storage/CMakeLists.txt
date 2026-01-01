add_library(hepatizon_storage_sqlite STATIC
    sqlite/sqlite_anchor.cpp
)

target_link_libraries(hepatizon_storage_sqlite
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
)

hepc_set_common_warnings(hepatizon_storage_sqlite)

add_library(hepatizon_storage_json STATIC
    json/json_anchor.cpp
)

target_link_libraries(hepatizon_storage_json
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
)

hepc_set_common_warnings(hepatizon_storage_json)

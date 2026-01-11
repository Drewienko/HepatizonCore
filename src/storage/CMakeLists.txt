add_library(hepatizon_storage_sqlite STATIC
    sqlite/sqlite_anchor.cpp
    sqlite/SqliteStorageRepository.cpp
)

target_link_libraries(hepatizon_storage_sqlite
    PUBLIC
        hepatizon_interfaces
        hepatizon_security
    PRIVATE
        hepatizon_adapters_headers
)

if(HEPC_STORAGE_USE_SQLCIPHER)
    find_package(sqlcipher CONFIG REQUIRED)
    target_compile_definitions(hepatizon_storage_sqlite PRIVATE HEPC_STORAGE_USE_SQLCIPHER=1)
    target_link_libraries(hepatizon_storage_sqlite PRIVATE sqlcipher::sqlcipher)
else()
    find_package(unofficial-sqlite3 CONFIG REQUIRED)
    target_link_libraries(hepatizon_storage_sqlite PRIVATE unofficial::sqlite3::sqlite3)
endif()

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

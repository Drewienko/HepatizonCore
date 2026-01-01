add_library(hepatizon_security STATIC
    security_anchor.cpp
    MemoryWiper.cpp
    SecureRandom.cpp
)

target_link_libraries(hepatizon_security
    PUBLIC
        hepatizon_interfaces
)

if(WIN32)
    target_link_libraries(hepatizon_security PRIVATE Bcrypt)
endif()

hepc_set_common_warnings(hepatizon_security)

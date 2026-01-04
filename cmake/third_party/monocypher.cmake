set(HEPC_MONOCYPHER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher-src")
set(HEPC_MONOCYPHER_SRC_DIR "${HEPC_MONOCYPHER_DIR}/src")

if(EXISTS "${HEPC_MONOCYPHER_SRC_DIR}/monocypher.c" AND EXISTS "${HEPC_MONOCYPHER_SRC_DIR}/monocypher.h")
    add_library(hepatizon_vendor_monocypher STATIC
        "${HEPC_MONOCYPHER_SRC_DIR}/monocypher.c"
    )

    target_include_directories(hepatizon_vendor_monocypher
        PUBLIC
            "${HEPC_MONOCYPHER_SRC_DIR}"
    )

    # Third-party code: do not promote warnings to errors.
    # CI enables Werror/WX for project code, but we keep vendor builds tolerant.
    if(MSVC)
        target_compile_options(hepatizon_vendor_monocypher PRIVATE /W3 /WX-)
    else()
        target_compile_options(hepatizon_vendor_monocypher PRIVATE -Wall -Wextra -Wpedantic)
        target_compile_options(hepatizon_vendor_monocypher PRIVATE -Wno-error)
    endif()
else()
    add_library(hepatizon_vendor_monocypher INTERFACE)
    target_include_directories(hepatizon_vendor_monocypher
        INTERFACE
            "${HEPC_MONOCYPHER_SRC_DIR}"
    )
    message(STATUS "Monocypher sources missing: run `git submodule update --init --recursive`")
endif()

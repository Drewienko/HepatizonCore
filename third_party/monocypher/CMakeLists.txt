if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/monocypher.c" AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/monocypher.h")
    add_library(hepatizon_vendor_monocypher STATIC
        monocypher.c
    )

    target_include_directories(hepatizon_vendor_monocypher
        PUBLIC
            "${CMAKE_CURRENT_LIST_DIR}"
    )

    if(COMMAND hepc_set_common_warnings)
        hepc_set_common_warnings(hepatizon_vendor_monocypher)
    endif()
else()
    add_library(hepatizon_vendor_monocypher INTERFACE)
    target_include_directories(hepatizon_vendor_monocypher
        INTERFACE
            "${CMAKE_CURRENT_LIST_DIR}"
    )
    message(STATUS "Monocypher sources missing: add third_party/monocypher/monocypher.c and third_party/monocypher/monocypher.h")
endif()

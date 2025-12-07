cmake_minimum_required(VERSION 3.20)

project(OnyxCitadel
    VERSION 0.0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ONYC_BUILD_CLI "Build the CLI application" ON)
option(ONYC_BUILD_GUI "Build the GUI application (Qt6)" OFF)
option(ONYC_ENABLE_TESTS "Build tests" OFF)
option(ONYC_ENABLE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

function(onyc_set_common_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(ONYC_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(ONYC_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

add_subdirectory(src)

if(ONYC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

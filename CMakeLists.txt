cmake_minimum_required(VERSION 3.20)

project(HepatizonCore
    VERSION 0.0.1
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(HEPC_BUILD_CLI "Build the CLI application" ON)
option(HEPC_BUILD_GUI "Build the GUI application (Qt6)" OFF)
option(HEPC_ENABLE_TESTS "Build tests" OFF)
option(HEPC_ENABLE_OPENSSL "Enable OpenSSL crypto provider" OFF)
option(HEPC_ENABLE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(HEPC_ENABLE_SANITIZERS "Enable ASan+UBSan (Clang/GCC only)" OFF)
option(HEPC_STORAGE_USE_SQLCIPHER "Use SQLCipher for the SQLite storage adapter (Windows-only via vcpkg)" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(HEPC_ENABLE_OPENSSL)
    find_package(OpenSSL REQUIRED)
endif()

function(hepc_set_common_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(HEPC_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(HEPC_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()

        if(HEPC_ENABLE_SANITIZERS)
            target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

add_subdirectory(third_party/monocypher)
add_subdirectory(src)

if(HEPC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

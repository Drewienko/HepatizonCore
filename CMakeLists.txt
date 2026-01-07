cmake_minimum_required(VERSION 3.20)

project(HepatizonCore
    VERSION 0.0.2
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(HEPC_BUILD_CLI "Build the CLI application" ON)
option(HEPC_BUILD_GUI "Build the GUI application (Qt6)" ON)
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

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/third_party/monocypher.cmake")
add_subdirectory(src)

if(HEPC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(CMAKE_CXX_FLAGS MATCHES "--coverage")
    find_program(GCOVR_PATH gcovr)

    if(GCOVR_PATH)
        add_custom_target(coverage

            COMMAND ctest --output-on-failure
            

            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/coverage-report


            COMMAND ${GCOVR_PATH} -r ${CMAKE_SOURCE_DIR}
                    --object-directory ${CMAKE_BINARY_DIR}
                    --html-details ${CMAKE_SOURCE_DIR}/coverage-report/index.html
                    --exclude "tests/"
                    --exclude "vcpkg/"
                    --exclude "third_party/"
                    --exclude "out/"
                    --exclude "src/ui/cli/main.cpp"
                    --exclude "src/ui/gui/main.cpp"  
                    --exclude ".*_autogen/"
                    --exclude-directories ".*CompilerId.*"
                    --gcov-ignore-errors=no_working_dir_found
            

            COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated: ${CMAKE_SOURCE_DIR}/coverage-report/index.html"
            
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Running tests and generating code coverage report..."
        )
    else()
        message(WARNING "gcovr not found! 'coverage' target will not be available.")
    endif()
endif()

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

if(GTest_FOUND)
    add_executable(onyxcitadel_tests
        unit/sample_test.cpp
    )
    target_link_libraries(onyxcitadel_tests PRIVATE GTest::gtest GTest::gtest_main onyxcitadel_core)
    onyc_set_common_warnings(onyxcitadel_tests)
    add_test(NAME onyxcitadel_tests COMMAND onyxcitadel_tests)
else()
    message(STATUS "GTest not found; skipping tests target.")
endif()

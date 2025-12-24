find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

if(GTest_FOUND)
    add_executable(hepatizoncore_tests
        unit/sample_test.cpp
    )
    target_link_libraries(hepatizoncore_tests PRIVATE GTest::gtest GTest::gtest_main hepatizoncore_core)
    hepc_set_common_warnings(hepatizoncore_tests)
    add_test(NAME hepatizoncore_tests COMMAND hepatizoncore_tests)
else()
    message(STATUS "GTest not found; skipping tests target.")
endif()


if (BUILD_CPPREST_EXTERNAL)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../external/cpprestsdk)
else()
    find_package(cpprestsdk CONFIG REQUIRED)
    find_package(Boost 1.65 COMPONENTS system REQUIRED)
endif()

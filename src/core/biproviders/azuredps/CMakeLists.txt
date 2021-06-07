
project(azuredps LANGUAGES CXX)

add_library(azure_dps_service_client
    STATIC
    ""
)

if (BUILD_CPPREST_EXTERNAL)
    find_package(Threads REQUIRED)

    add_dependencies(azure_dps_service_client 
        cpprestsdk)

    add_library(cpprestsdk_external SHARED IMPORTED)
    set_target_properties(cpprestsdk_external PROPERTIES
        IMPORTED_LOCATION ${LIB_CPPREST_EXTERNAL}
    )

    target_link_libraries(azure_dps_service_client 
        PRIVATE
            cpprestsdk_external
            Threads::Threads
    )
else()
    target_link_libraries(azure_dps_service_client 
        PRIVATE
            cpprestsdk::cpprest
    )    
endif()

target_sources(azure_dps_service_client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/azure_dps_service_client.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/azure_dps_service_client_proxy.cpp
)

target_include_directories(azure_dps_service_client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../..
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../wifi
)

target_link_libraries(azure_dps_service_client
    PRIVATE
        OpenSSL::Crypto
        ${Boost_LIBRARIES}
)

target_sources(ztpcore
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider_azure_dps.c
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider_azure_dps_config.c
)

add_executable(sample_cpp
    ""
)

target_include_directories(sample_cpp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../..
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../wifi
)

target_sources(sample_cpp
    PRIVATE
        sample.cpp
)

target_link_libraries(sample_cpp
    PRIVATE
        azure_dps_service_client
)

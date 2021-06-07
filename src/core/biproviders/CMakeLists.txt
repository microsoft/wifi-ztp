
target_sources(ztpcore
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider.c
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider_settings.c
)

target_include_directories(ztpcore
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/azuredps
        ${CMAKE_CURRENT_SOURCE_DIR}/file
        ${CMAKE_CURRENT_SOURCE_DIR}/../../wifi
        ${CMAKE_CURRENT_SOURCE_DIR}/../../utils
)

add_subdirectory(azuredps)
add_subdirectory(file)


target_sources(ztpcore
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider_file.c
        ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap_info_provider_file_config.c
)

target_include_directories(ztpcore
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils
)


project(ztpwifi)

add_library(ztpwifi
    STATIC
    ""
)

target_sources(ztpwifi
    PRIVATE
        dpp.c
)

target_include_directories(ztpwifi
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

target_link_libraries(ztpwifi
    ztputils
)

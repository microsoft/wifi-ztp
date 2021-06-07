
project(ztpsystemd)

add_library(ztpsystemd
    STATIC
    ""
)

target_sources(ztpsystemd
    PRIVATE
        ztp_systemd.c
)

target_include_directories(ztpsystemd
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

target_link_libraries(ztpsystemd
    ${LIBSYSTEMD_TARGET}
)


project(ztputils)

add_library(ztputils
    STATIC
    ""
)

target_sources(ztputils
    PRIVATE
        file_utils.c
        json_parse.c
        led_ctrl.c
        string_utils.c
        time_utils.c
        event_loop.c
)

target_include_directories(ztputils
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

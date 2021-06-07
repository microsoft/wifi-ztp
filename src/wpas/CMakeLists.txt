
project(ztpwpas)

add_library(ztpwpas
    STATIC
    ""
)

if (BUILD_HOSTAP_EXTERNAL)
    add_dependencies(ztpwpas hostap)
endif()

target_sources(ztpwpas
    PRIVATE
        wpa_controller.c
        wpa_controller_watcher.c
        wpa_core.c
        wpa_supplicant.c
)

target_include_directories(ztpwpas
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../utils
        ${CMAKE_CURRENT_SOURCE_DIR}/../wifi
)

target_link_libraries(ztpwpas
    ${LIBWPA_CLIENT_TARGET}
    ztputils
)

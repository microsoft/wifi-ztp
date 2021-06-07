
project(ztpd)

add_executable(ztpd
    ""
)

install(
    TARGETS ztpd 
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

target_sources(ztpd
    PRIVATE
        main.c
        ztpd_ui.c
        ztpd.c
)

target_include_directories(ztpd
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../core
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/biproviders
        ${CMAKE_CURRENT_SOURCE_DIR}/../dbus
        ${CMAKE_CURRENT_SOURCE_DIR}/../systemd
        ${CMAKE_CURRENT_SOURCE_DIR}/../utils
        ${CMAKE_CURRENT_SOURCE_DIR}/../wpas
        ${CMAKE_CURRENT_SOURCE_DIR}/../wifi
)

target_link_libraries(ztpd
    ztpcore
    ztpdbus
    ztpsystemd
    ztputils
    ${LIBGPIOD_TARGET}
)

add_subdirectory(systemd)

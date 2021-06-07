
project(ztpdbus)

add_library(ztpdbus
    STATIC
    ""
)

target_sources(ztpdbus
    PRIVATE
        dbus_message_helpers.c
        ztp_dbus_configurator.c
        ztp_dbus_network_configuration.c
        ztp_dbus_client.c
        ztp_dbus_server.c
)

target_include_directories(ztpdbus
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../core
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/biproviders
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/biproviders/file
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/biproviders/azuredps
        ${CMAKE_CURRENT_SOURCE_DIR}/../utils
        ${CMAKE_CURRENT_SOURCE_DIR}/../wpas
        ${CMAKE_CURRENT_SOURCE_DIR}/../wifi
)

target_link_libraries(ztpdbus
    ztpcore
)

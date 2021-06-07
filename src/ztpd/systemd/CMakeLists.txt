
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ztpd.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/ztpd.service
)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ztpd.service
    DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/systemd/system
)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/com.microsoft.ztp1.service
    DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/system-services
)

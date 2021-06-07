find_library(LIBSYSTEMD
    NAMES libsystemd.so
    REQUIRED)

if(LIBSYSTEMD)
    set(LIBSYSTEMD_TARGET ${LIBSYSTEMD})
    MESSAGE(STATUS "Found systemd: ${LIBSYSTEMD}")
endif()

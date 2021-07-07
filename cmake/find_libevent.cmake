find_library(LIBEVENT
    NAMES libevent.so
    REQUIRED)

if(LIBGPIOD)
    set(LIBEVENT_TARGET ${LIBEVENT})
    MESSAGE(STATUS "Found libevent: ${LIBEVENT}")
endif()

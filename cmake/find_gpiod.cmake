find_library(LIBGPIOD
    NAMES libgpiod.so
    REQUIRED)

if(LIBGPIOD)
    set(LIBGPIOD_TARGET ${LIBGPIOD})
    MESSAGE(STATUS "Found libgpiod: ${LIBGPIOD}")
endif()

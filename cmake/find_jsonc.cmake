find_library(LIBJSONC
    NAMES libjson-c.so
    REQUIRED)

if(LIBJSONC)
    set(LIBJSONC_TARGET ${LIBJSONC})
    MESSAGE(STATUS "Found json-c: ${LIBJSONC}")
endif()

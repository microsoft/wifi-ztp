# project options
cmake_minimum_required(VERSION 3.10)
project(ztp C CXX)

option(
    BUILD_CPPREST_EXTERNAL 
    "Build cpprestsdk from built-in external source" 
    ON
)

option(
    BUILD_HOSTAP_EXTERNAL
    "Build wpa_supplicant/hostapd from built-in external source"
    ON
)

option(
    WERROR
    "Treat compiler warnings as errors"
    ON
)

# specify the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CheckCCompilerFlag)
include(ExternalProject)
include(GNUInstallDirs)
include(cmake/find_git.cmake)
include(cmake/find_openssl.cmake)
include(cmake/find_cpprest.cmake)
include(cmake/find_wpa_client.cmake)
include(cmake/find_systemd.cmake)
include(cmake/find_gpiod.cmake)
include(cmake/find_jsonc.cmake)
include(cmake/find_libevent.cmake)
include(cmake/security_hardening.cmake)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(
    -Wall 
    -Wshadow
    -Wformat-security
    -Wextra
    -Wpedantic
    -Wconversion
)

if (WERROR)
    add_compile_options(-Werror)
endif()

add_subdirectory(src)

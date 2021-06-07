
set(CPPREST_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/cpprestsdk-prefix/src/cpprestsdk/Release)

ExternalProject_Add(cpprestsdk
    GIT_REPOSITORY "https://github.com/microsoft/cpprestsdk.git"
    GIT_TAG "d9d7f5ed4f5b0ed2d40eed2b266c797bc5ceadf6"
    BINARY_DIR ${CPPREST_PREFIX}
    INSTALL_DIR ${CPPREST_PREFIX}
    CMAKE_ARGS 
        -DBUILD_SAMPLES=OFF 
        -DBUILD_TESTS=OFF 
        -DCMAKE_BUILD_TYPE=Release 
        -DCPPREST_EXCLUDE_BROTLI=OFF
        -DCPPREST_EXPORT_DIR=cmake/cpprestsdk
        -Wno-dev -DWERROR=OFF
        -DWERROR=OFF
)

set(LIB_CPPREST_EXTERNAL_LIBS
    "${CPPREST_PREFIX}/Release/Binaries"
    CACHE PATH
    "Directory of external cpprestsdk libraries"
)
set(LIB_CPPREST_EXTERNAL_NAME
    cpprest
    CACHE STRING
    "cpprestsdk shared object name"
)
set(LIB_CPPREST_EXTERNAL
    ${LIB_CPPREST_EXTERNAL_LIBS}/lib${LIB_CPPREST_EXTERNAL_NAME}.so
    CACHE FILEPATH
    "cpprestsdk shared object"
)

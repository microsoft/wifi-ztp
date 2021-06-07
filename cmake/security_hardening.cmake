set(C_COMPILER_HARDENING_FLAGS "")

if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    check_c_compiler_flag(-fstack-protector HAS_STACK_PROTECTOR)

    if (HAS_STACK_PROTECTOR)
        set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -fstack-protector")
    endif()

    set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -fvisibility=hidden")
elseif (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    check_c_compiler_flag(-fstack-clash-protection HAS_STACK_CLASH_PROTECTION)
    check_c_compiler_flag(-fstack-protector-all HAS_STACK_PROTECTOR_ALL)
    check_c_compiler_flag(-fvisibility=hidden HAS_VISIBILITY)

    if (HAS_STACK_CLASH_PROTECTION)
        set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -fstack-clash-protection")
    endif()

    if (HAS_STACK_PROTECTOR_ALL)
        set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -fstack-protector-all")
    endif()

    if (HAS_VISIBILITY)
        set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -fvisibility=hidden")
    endif()

    set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -Wl,-z,noexecstack")
    set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -Wl,-z,now")
    set(C_COMPILER_HARDENING_FLAGS "${C_COMPILER_HARDENING_FLAGS} -Wl,-z,relro")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMPILER_HARDENING_FLAGS}")

if (CMAKE_BUILD_TYPE MATCHES "(Release|RelWithDebInfo|MinSizeRel)")
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()
# Build for the SGXLogicSanitizer runtime support library.

include_directories(..)

set(SLSAN_SOURCES slsan_rtl.cpp slsan_interceptors.cpp)
set(SLSAN_STATIC_SOURCES slsan_rtl_static.cpp)

set(SLSAN_COMMON_CFLAGS ${SANITIZER_COMMON_CFLAGS})

append_rtti_flag(OFF SLSAN_COMMON_CFLAGS)
append_list_if(COMPILER_RT_HAS_FFREESTANDING_FLAG -ffreestanding SLSAN_COMMON_CFLAGS)

# Build SLSan runtimes shipped with Clang.
add_compiler_rt_component(slsan)

add_compiler_rt_runtime(clang_rt.slsan_static
    STATIC
    ARCHS ${SLSAN_SUPPORTED_ARCH}
    SOURCES ${SLSAN_STATIC_SOURCES}
    CFLAGS ${SLSAN_CFLAGS}
    PARENT_TARGET slsan)

foreach(arch ${SLSAN_SUPPORTED_ARCH})
    set(SLSAN_CFLAGS ${SLSAN_COMMON_CFLAGS})
    append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE SLSAN_CFLAGS)

    add_compiler_rt_runtime(
        clang_rt.slsan
        STATIC
        ARCHS ${arch}
        SOURCES ${SLSAN_SOURCES}
        OBJECT_LIBS RTInterception
                    RTSanitizerCommon
                    RTSanitizerCommonLibc
                    RTSanitizerCommonSymbolizer
        CFLAGS ${SLSAN_CFLAGS}
        PARENT_TARGET slsan
    )

    add_sanitizer_rt_symbols(
        clang_rt.slsan
        ARCHS ${arch}
        EXTRA slsan.syms.extra
    )

    add_dependencies(
        slsan
        clang_rt.slsan-${arch}-symbols
    )
endforeach()

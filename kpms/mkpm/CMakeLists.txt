# mkpm: the single merged KPM (hide-so + wxshadow + dysvcpit).
# Per-module standalone targets were removed; only mkpm.kpm is built.
add_kpm_module(mkpm
    main.c
    compat/libc_shim.c
    ../hide-maps/hidemaps.c
    ../wxshadow/wxshadow.c
    ../wxshadow/wxshadow_pgtable.c
    ../wxshadow/wxshadow_handlers.c
    ../wxshadow/wxshadow_bp.c
    ../wxshadow/wxshadow_scan.c
    dysvcpit/sysmon.c
    dysvcpit/opts.c
    dysvcpit/ehide.c
    dysvcpit/eredirect.c
    dysvcpit/evm.c
    dysvcpit/emaps.c
    antidetect/antidetect.c
    antidetect/supercall.c
)

# merged build: strip per-module KPM entry macros, export init/ctl0/exit
target_compile_definitions(mkpm_obj PRIVATE MKPM_MERGED)

# extra upstream linux headers missing from the KP kernel tree (dysvcpit needs them)
target_include_directories(mkpm_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/compat)

# map plain memcpy/memset/... onto KP kfuncs so the loader can resolve them
target_compile_options(mkpm_obj PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/compat/kf_string_map.h)

# libc_shim.c must NOT see the static-inline definitions in <linux/string.h>:
# predefine its include guard so the forced include chain expands to nothing.
set_source_files_properties(compat/libc_shim.c PROPERTIES
    COMPILE_DEFINITIONS "_LINUX_STRING_H_")

# wxshadow userspace client (not a KPM, kept from the old wxshadow target)
add_executable(wxshadow_client ../wxshadow/wxshadow_client.c)
target_link_options(wxshadow_client PRIVATE -static -s)

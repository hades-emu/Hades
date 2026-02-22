################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2026 - The Hades Authors
##
################################################################################

libapp_extra_cflags = [
    '-DCIMGUI_DEFINE_ENUMS_AND_STRUCTS',
]
libapp_extra_deps = []

libapp_sources = [
    'shaders/frag-color-correction.c',
    'shaders/frag-grey-scale.c',
    'shaders/frag-lcd-grid-with-rgb-stripes.c',
    'shaders/frag-lcd-grid.c',
    'shaders/vertex-common.c',
    'windows/game.c',
    'windows/menubar.c',
    'windows/notification.c',
    'windows/settings.c',
    'args.c',
    'audio.c',
    'bindings.c',
    'config.c',
    'emulator.c',
    'event.c',
    'main.c',
    'nfd.c',
    'path.c',
    'video.c',
]

libapp_dbg_sources = [
    'dbg/cmd/apu.c',
    'dbg/cmd/break.c',
    'dbg/cmd/context.c',
    'dbg/cmd/continue.c',
    'dbg/cmd/disas.c',
    'dbg/cmd/exit.c',
    'dbg/cmd/frame.c',
    'dbg/cmd/help.c',
    'dbg/cmd/io.c',
    'dbg/cmd/key.c',
    'dbg/cmd/ppu.c',
    'dbg/cmd/print.c',
    'dbg/cmd/registers.c',
    'dbg/cmd/reset.c',
    'dbg/cmd/screenshot.c',
    'dbg/cmd/step.c',
    'dbg/cmd/trace.c',
    'dbg/cmd/verbose.c',
    'dbg/cmd/watch.c',
    'dbg/lang/eval.c',
    'dbg/lang/lexer.c',
    'dbg/lang/parser.c',
    'dbg/lang/utils.c',
    'dbg/lang/variables.c',
    'dbg/dbg.c',
    'dbg/io.c',
]

libapp = static_library(
    'libapp',
    libapp_sources,
    dependencies: [
        dependency('threads', required: true, static: static_dependencies),
        dependency('libarchive', version: '>=3.0', required: true, static: static_dependencies or get_option('static_libarchive')),
    ] + imgui_dep,
    link_with: [libgba, imgui, mjson] + libapp_extra_deps,
    include_directories: [incdir, imgui_inc, mjson_inc, stb_inc],
    c_args: cflags + libapp_extra_cflags,
    link_args: ldflags,
)

if get_option('with_debugger')
    libapp_dbg = static_library(
        'libapp_dbg',
        libapp_sources + libapp_dbg_sources,
        dependencies: [
            dependency('threads', required: true, static: static_dependencies),
            dependency('libarchive', version: '>=3.0', required: true, static: static_dependencies or get_option('static_libarchive')),
            dependency('libedit', required: true, static: static_dependencies),
            dependency('capstone', required: true, static: static_dependencies),
        ] + imgui_dep,
        link_with: [libgba_dbg, imgui, mjson] + libapp_extra_deps,
        include_directories: [incdir, imgui_inc, mjson_inc, stb_inc],
        c_args: cflags + libapp_extra_cflags + debugger_cflags,
        link_args: ldflags + debugger_ldflags,
    )
endif

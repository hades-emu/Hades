################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2023 - The Hades Authors
##
################################################################################

libapp_extra_cflags = [
    '-DCIMGUI_DEFINE_ENUMS_AND_STRUCTS',
]
libapp_extra_deps = []

###############################
##         Debugger          ##
###############################

if get_option('with_debugger')
    libdbg = static_library(
        'dbg',
        'dbg/cmd/break.c',
        'dbg/cmd/context.c',
        'dbg/cmd/continue.c',
        'dbg/cmd/disas.c',
        'dbg/cmd/exit.c',
        'dbg/cmd/frame.c',
        'dbg/cmd/help.c',
        'dbg/cmd/io.c',
        'dbg/cmd/key.c',
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
        dependencies: [
            dependency('libedit', required: true, static: static_dependencies),
            dependency('capstone', required: true, static: static_dependencies),
        ],
        include_directories: [incdir, imgui_inc],
        c_args: cflags + libapp_extra_cflags,
        link_args: ldflags,
    )

    libapp_extra_deps += [libdbg]
endif

###############################
## Graphical User Interface  ##
###############################

libapp = static_library(
    'app',
    'sdl/audio.c',
    'sdl/event.c',
    'sdl/init.c',
    'sdl/video.c',
    'shaders/frag-color-correction.c',
    'shaders/frag-lcd-grid.c',
    'shaders/vertex-common.c',
    'windows/game.c',
    'windows/keybinds.c',
    'windows/menubar.c',
    'windows/notif.c',
    'args.c',
    'config.c',
    'emulator.c',
    'bindings.c',
    'main.c',
    dependencies: [
        dependency('threads', required: true, static: static_dependencies),
        dependency('libarchive', version: '>=3.0', required: true, static: static_dependencies or get_option('static_libarchive')),
    ] + imgui_dep,
    link_with: [libgba, imgui, nfde, mjson] + libapp_extra_deps,
    include_directories: [incdir, imgui_inc, nfde_inc, mjson_inc, stb_inc],
    c_args: cflags + libapp_extra_cflags,
    link_args: ldflags,
)

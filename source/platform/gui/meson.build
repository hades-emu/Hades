################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################


gui_sources = [
    'features/config.c',
    'features/screenshot.c',
    'sdl/audio.c',
    'sdl/init.c',
    'sdl/input.c',
    'sdl/video.c',
    'windows/error.c',
    'windows/menubar.c',
    'windows/game.c',
    'game.c',
    'main.c',
]

gui_deps = [
    dependency('threads', required: true, static: get_option('static_executable')),
]

if get_option('with_debugger')
    gui_sources += [
        'debugger/cmd/break.c',
        'debugger/cmd/context.c',
        'debugger/cmd/continue.c',
        'debugger/cmd/disas.c',
        'debugger/cmd/exit.c',
        'debugger/cmd/help.c',
        'debugger/cmd/print.c',
        'debugger/cmd/registers.c',
        'debugger/cmd/reset.c',
        'debugger/cmd/step.c',
        'debugger/cmd/trace.c',
        'debugger/cmd/verbose.c',
        'debugger/cmd/watch.c',
        'debugger/lang/eval.c',
        'debugger/lang/lexer.c',
        'debugger/lang/parser.c',
        'debugger/lang/utils.c',
        'debugger/lang/variables.c',
        'debugger/debugger.c',
    ]

    gui_deps += [
        dependency('libedit', required: true, static: get_option('static_executable')),
        dependency('capstone', required: true, static: get_option('static_executable')),
    ]
endif

libgui = static_library(
    'gui',
    gui_sources,
    dependencies: gui_deps,
    link_with: [libgba, libcommon, imgui, nfde, mjson],
    include_directories: [incdir, imgui_inc, nfde_inc, mjson_inc, stb_inc],
    c_args: cflags,
    link_args: ldflags,
)
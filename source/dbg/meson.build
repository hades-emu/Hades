################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

libdbg = static_library(
    'dbg',
    'cmd/break.c',
    'cmd/context.c',
    'cmd/continue.c',
    'cmd/disas.c',
    'cmd/exit.c',
    'cmd/help.c',
    'cmd/print.c',
    'cmd/registers.c',
    'cmd/reset.c',
    'cmd/step.c',
    'cmd/trace.c',
    'cmd/verbose.c',
    'cmd/watch.c',
    'lang/eval.c',
    'lang/lexer.c',
    'lang/parser.c',
    'lang/utils.c',
    'lang/variables.c',
    'dbg.c',
    dependencies: [
        dependency('libedit', required: true, static: get_option('static_executable')),
        dependency('capstone', required: true, static: get_option('static_executable')),
    ],
    link_with: [libcommon],
    include_directories: [incdir, imgui_inc],
    c_args: cflags,
    link_args: ldflags,
)
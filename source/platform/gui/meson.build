################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

libgui = static_library(
    'gui',
    'game/game.c',
    'game/render.c',
    'game/screenshot.c',
    'config.c',
    'error.c',
    'main.c',
    'menubar.c',
    dependencies: [
        dependency('threads', required: true, static: get_option('static_executable')),
    ],
    link_with: [libgba, imgui, libcommon, frozen, nfde],
    include_directories: [incdir, imgui_inc, frozen_inc, stb_inc, nfde_inc],
    c_args: cflags,
    link_args: ldflags,
)
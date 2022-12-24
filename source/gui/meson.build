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
    'config.c',
    'sdl/audio.c',
    'sdl/init.c',
    'sdl/input.c',
    'sdl/video.c',
    'windows/error.c',
    'windows/menubar.c',
    'windows/game.c',
    dependencies: [
        dependency('threads', required: true, static: get_option('static_executable')),
    ],
    link_with: [libgba, libcommon, imgui, nfde, mjson],
    include_directories: [incdir, imgui_inc, nfde_inc, mjson_inc],
    c_args: cflags,
    link_args: ldflags,
)

################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

libguicommon = static_library(
    'gui-common',
    'game.c',
    dependencies: [
        dependency('threads', required: true, static: get_option('static_executable')),
    ],
    link_with: [],
    include_directories: [incdir, imgui_inc],
    c_args: cflags,
    link_args: ldflags,
)
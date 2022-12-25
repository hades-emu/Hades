################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2023 - The Hades Authors
##
################################################################################

libcommon = static_library(
    'common',
    'game.c',
    'log.c',
    'utils.c',
    include_directories: [incdir, imgui_inc, stb_inc],
    c_args: cflags,
    link_args: ldflags,
)

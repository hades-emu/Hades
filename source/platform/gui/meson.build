################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

if host_machine.system() == 'windows'
    hades_name = 'Hades'
else
    hades_name = 'hades'
endif

hades = executable(
    hades_name,
    'game/game.c',
    'game/render.c',
    'game/screenshot.c',
    'config.c',
    'error.c',
    'main.c',
    'menubar.c',
    winrc,  # Empty on non-windows system
    dependencies: [
        dependency('threads', required: true, static: get_option('static_executable')),
        cc.find_library('m', required: true, static: get_option('static_executable')),
    ],
    link_with: [libgba, imgui, libcommon, frozen],
    include_directories: [incdir, imgui_inc, frozen_inc, stb_inc],
    c_args: cflags,
    link_args: ldflags,
    gui_app: true,
    install: true,
)
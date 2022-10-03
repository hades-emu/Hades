################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

project(
    'Hades',
    'c',
    'cpp',
    version: '0.0.1',
    license: 'GPL-2.0-only',
    default_options: ['c_std=gnu17', 'cpp_std=c++11', 'buildtype=release'],
)

incdir = include_directories('include', 'source')
cflags = [
    '-fms-extensions',
    '-Wno-microsoft-anon-tag',
    '-DHADES_VERSION="@0@"'.format(meson.project_version()),
    # '-fsanitize=undefined',
]
ldflags = [
    # '-fsanitize=undefined',
]

if get_option('static_executable')
    cflags += ['-static']
    ldflags += ['-static']
endif

if get_option('with_debugger')
    cflags += ['-DWITH_DEBUGGER']
    ldflags += ['-DWITH_DEBUGGER']
endif

cc = meson.get_compiler('c')

###############################
##   External Dependencies   ##
###############################

subdir('external')

###############################
##      Common Library       ##
###############################

subdir('source/common')

###############################
##         Debugger          ##
###############################

if get_option('with_debugger')
    subdir('source/dbg')
endif

###############################
## GBA Emulator Core Library ##
###############################

subdir('source/gba')

###############################
## Graphical User Interface  ##
###############################

subdir('source/gui')

hades_extra_deps = []

if get_option('with_debugger')
    hades_extra_deps += [libdbg]
endif

if host_machine.system() == 'windows'
    winrc = import('windows').compile_resources('./resource/windows/hades.rc')

    hades = executable(
        'Hades',
        'source/main.c',
        winrc,
        gui_app: true,
        link_with: [libgui] + hades_extra_deps,
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )
elif host_machine.system() == 'darwin'
    hades = executable(
        'hades',
        'source/main.c',
        link_with: [libgui] + hades_extra_deps,
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )

    install_data('./resource/macos/Info.plist', install_dir: 'Contents')
    install_data('./resource/macos/hades.icns', install_dir: 'Contents/Resources')
    install_data('./resource/macos/run.sh',     install_dir: 'Contents/MacOS')
else  # Linux and all others (eventually)
    hades = executable(
        'hades',
        'source/main.c',
        link_with: [libgui] + hades_extra_deps,
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )
endif
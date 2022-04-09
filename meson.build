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
]
ldflags = []

if get_option('static_executable')
    cflags += ['-static']
    ldflags += ['-static']
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
## GBA Emulator Core Library ##
###############################

subdir('source/gba')

###############################
## Graphical User Interface  ##
###############################

subdir('source/platform/gui')

if host_machine.system() == 'windows'
    winrc = import('windows').compile_resources('./resource/windows/hades.rc')

    hades = executable(
        'Hades',
        winrc,
        gui_app: true,
        link_with: [libgba, imgui, libcommon, frozen, libgui],
        install: true,
    )
else
    hades = executable(
        'hades',
        link_with: [libgba, imgui, libcommon, frozen, libgui],
        install: true,
    )
endif

if host_machine.system() == 'darwin'
    install_data('./resource/macos/Info.plist', install_dir: 'Contents')
    install_data('./resource/macos/hades.icns', install_dir: 'Contents/Resources')
    install_data('./resource/macos/run.sh',     install_dir: 'Contents/MacOS')
endif

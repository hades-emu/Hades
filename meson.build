################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2023 - The Hades Authors
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

static_dependencies = get_option('static_executable') or get_option('static_dependencies')

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
## GBA Emulator Core Library ##
###############################

subdir('source/gba')

###############################
##        Application        ##
###############################

subdir('source/app')

if host_machine.system() == 'windows'
    winrc = import('windows').compile_resources('./resource/windows/hades.rc')

    hades = executable(
        'Hades',
        'source/log.c',
        winrc,
        win_subsystem: 'windows',
        link_with: [libapp],
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )
elif host_machine.system() == 'darwin'
    hades = executable(
        'hades',
        'source/log.c',
        link_with: [libapp],
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )

    install_data('./resource/macos/Info.plist', install_dir: 'Contents')
    install_data('./resource/macos/hades.icns', install_dir: 'Contents/Resources')
    install_data('./resource/macos/run.sh',     install_dir: 'Contents/MacOS')
elif host_machine.system() == 'linux'  # Linux
    hades = executable(
        'hades',
        'source/log.c',
        link_with: [libapp],
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )

    install_data('./resource/linux/hades.desktop', install_dir: 'share/applications')
    install_data('./resource/linux/hades.png', install_dir: 'share/icons/hicolor/256x256/apps')
else # Not supported officially, but there's no reason not to try and build them anyway
    hades = executable(
        'hades',
        'source/log.c',
        link_with: [libapp],
        include_directories: [incdir, imgui_inc],
        c_args: cflags,
        link_args: ldflags,
        install: true,
    )
endif

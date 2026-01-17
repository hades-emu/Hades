################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2024 - The Hades Authors
##
################################################################################

project(
    'Hades',
    'c',
    'cpp',
    version: '1.1.0',
    license: 'GPL-2.0-only',
    default_options: ['c_std=gnu17', 'cpp_std=c++11', 'buildtype=release'],
)

cc = meson.get_compiler('c')
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

# Somewhat required for the Windows CI to link properly.
# Otherwise it complains about a missing `WinMain()` function that SDL3 is, afaik, supposed to provide.
if host_machine.system() == 'windows' and cc.has_define('__MINGW32__')
    ldflags += [
        '-lmingw32',
    ]
endif

static_dependencies = get_option('static_executable') or get_option('static_dependencies')

if get_option('static_executable')
    cflags += ['-static']
    ldflags += ['-static']
endif

if get_option('with_wayland')
    cflags += ['-DWITH_WAYLAND']
    ldflags += ['-DWITH_WAYLAND']
endif

debugger_cflags = ['-DWITH_DEBUGGER']
debugger_ldflags = ['-DWITH_DEBUGGER']

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

    if get_option('with_debugger')
        hades = executable(
            'Hades Debugger',
            'source/log.c',
            winrc,
            win_subsystem: 'windows',
            link_with: [libapp_dbg],
            include_directories: [incdir, imgui_inc],
            c_args: cflags + debugger_cflags,
            link_args: ldflags + debuffer_ldflags,
            install: true,
        )
    endif

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

    if get_option('with_debugger')
        hades_dbg = executable(
            'hades-dbg',
            'source/log.c',
            link_with: [libapp_dbg],
            include_directories: [incdir, imgui_inc],
            c_args: cflags + debugger_cflags,
            link_args: ldflags + debugger_ldflags,
            install: true,
        )
    endif

    install_data('./resource/macos/Info.plist', install_dir: 'Contents')
    install_data('./resource/macos/hades.icns', install_dir: 'Contents/Resources')
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

    if get_option('with_debugger')
        hades_dbg = executable(
            'hades-dbg',
            'source/log.c',
            link_with: [libapp_dbg],
            include_directories: [incdir, imgui_inc],
            c_args: cflags + debugger_cflags,
            link_args: ldflags + debugger_ldflags,
            install: true,
        )
    endif

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

    if get_option('with_debugger')
        hades_dbg = executable(
            'hades-dbg',
            'source/log.c',
            link_with: [libapp_dbg],
            include_directories: [incdir, imgui_inc],
            c_args: cflags + debugger_cflags,
            link_args: ldflags + debugger_ldflags,
            install: true,
        )
    endif
endif

################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021 - The Hades Authors
##
################################################################################

gui_incdir = include_directories(
    'external/cimgui/',
    'external/cimgui/imgui/',
    'external/cimgui/generator/output/',
    'external/imgui_file_dialog/',
)

cflags += [
    '-DIMGUI_IMPL_API=extern "C"  ',
]
cxxflags = cflags

gui_dependencies = [
    dependency('threads', required: true, static: get_option('static_executable')),
    dependency('sdl2', version: '>=2', required: true, static: get_option('static_executable')),
    dependency('glew', required: true, static: get_option('static_executable')),
    meson.get_compiler('c').find_library('dl'),
]

if host_machine.system() == 'darwin'
    gui_dependencies += [
        dependency('appleframework', required: true, modules: 'OpenGL')
    ]
else
    gui_dependencies += [
        dependency('gl', required: true, static: get_option('static_executable')),
    ]
endif

hades = executable(
    'hades',
    'error.c',
    'main.c',
    'menubar.c',
    'game.c',
    'external/cimgui/cimgui.cpp',
    'external/cimgui/imgui/imgui.cpp',
    'external/cimgui/imgui/imgui_demo.cpp',
    'external/cimgui/imgui/imgui_draw.cpp',
    'external/cimgui/imgui/imgui_tables.cpp',
    'external/cimgui/imgui/imgui_widgets.cpp',
    'external/cimgui/imgui/backends/imgui_impl_opengl3.cpp',
    'external/cimgui/imgui/backends/imgui_impl_sdl.cpp',
    'external/imgui_file_dialog/ImGuiFileDialog.cpp',
    dependencies: gui_dependencies,
    include_directories: [incdir, gui_incdir],
    c_args: cflags,
    cpp_args: cxxflags,
    link_args: ldflags,
    link_with: libgba,
)
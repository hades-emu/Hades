################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021 - The Hades Authors
##
################################################################################

###############################
##     Cimgui + IGFD         ##
###############################

cflags += [
    '-DIMGUI_IMPL_API=extern "C"  ',
]

imgui_inc = include_directories(
    'cimgui/',
    'cimgui/imgui/',
    'cimgui/generator/output/',
    'imgui_file_dialog/',
)

imgui_dep = [
    dependency('sdl2', version: '>=2', required: true, static: get_option('static_executable')),
    dependency('SDL2_image', version: '>=2', required: true, static: get_option('static_executable')),
    dependency('glew', required: true, static: true),
]

if host_machine.system() == 'darwin'
    imgui_dep += [
        dependency('appleframeworks', required: true, modules: 'OpenGL')
    ]
else
    imgui_dep += [
        dependency('gl', required: true, static: get_option('static_executable')),
    ]
endif

if host_machine.system() != 'windows'
    imgui_dep += [
        cc.find_library('dl'),
    ]
endif

# For some reasons, static sdl2 on windows fail if we do not explicitely ask for its dependencies
if get_option('static_executable')
    dependencies += [
        dependency('libpng', required: true, static: true),
        dependency('libjpeg', required: true, static: true),
        dependency('libtiff-4', required: true, static: true),
        dependency('libwebp', required: true, static: true),
    ]
endif

#dlopen_dlsym_test_code = '''
##include <dlfcn.h>
##include <stdlib.h>
#
#int
#main(
#    int argc,
#    char const *argv[]
#) {
#    void *handle;
#    void *f;
#
#    handle = dlopen(NULL, 0);
#    f = dlsym(handle, "test");
#    return (0);
#}
#'''
#
#libdl_dep = []
#if cc.links(dlopen_dlsym_test_code, args: '-ldl')
#    imgui_dep += [
#        cc.find_library('dl'),
#    ]
#elif not cc.links(dlopen_dlsym_test_code)
#    error('Failed to find libdl')
#endif

imgui = static_library(
    'imgui',
    'cimgui/cimgui.cpp',
    'cimgui/imgui/imgui.cpp',
    'cimgui/imgui/imgui_demo.cpp',
    'cimgui/imgui/imgui_draw.cpp',
    'cimgui/imgui/imgui_tables.cpp',
    'cimgui/imgui/imgui_widgets.cpp',
    'cimgui/imgui/backends/imgui_impl_opengl3.cpp',
    'cimgui/imgui/backends/imgui_impl_sdl.cpp',
    'imgui_file_dialog/ImGuiFileDialog.cpp',
    include_directories: imgui_inc,
    dependencies: imgui_dep,
    c_args: cflags,
    cpp_args: cflags,
    link_args: ldflags,
)
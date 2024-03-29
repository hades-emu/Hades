################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021 - The Hades Authors
##
################################################################################

###############################
##          Cimgui           ##
###############################

cflags += [
    '-DIMGUI_IMPL_API=extern "C"  ',
    '-DCIMGUI_USE_OPENGL3',
    '-DCIMGUI_USE_SDL2',
]

imgui_inc = include_directories(
    'cimgui/',
    'cimgui/imgui/',
    'cimgui/generator/output/',
)

imgui_dep = [
    dependency('sdl2', version: '>=2', required: true, static: static_dependencies or get_option('static_sdl2')),
    dependency('glew', required: true, static: static_dependencies or get_option('static_glew')),
]

if host_machine.system() == 'darwin'
    imgui_dep += [
        dependency('appleframeworks', required: true, modules: 'OpenGL'),
    ]
else
    imgui_dep += [
        dependency('gl', required: true, static: static_dependencies),
    ]
endif

if static_dependencies
    cflags += [
        '-DGLEW_STATIC',
    ]
endif

if host_machine.system() != 'windows'
    imgui_dep += [
        cc.find_library('dl'),
    ]
endif

imgui = static_library(
    'imgui',
    'cimgui/cimgui.cpp',
    'cimgui/imgui/imgui.cpp',
    'cimgui/imgui/imgui_demo.cpp',
    'cimgui/imgui/imgui_draw.cpp',
    'cimgui/imgui/imgui_tables.cpp',
    'cimgui/imgui/imgui_widgets.cpp',
    'cimgui/imgui/backends/imgui_impl_opengl3.cpp',
    'cimgui/imgui/backends/imgui_impl_sdl2.cpp',
    include_directories: imgui_inc,
    dependencies: imgui_dep,
    c_args: cflags,
    cpp_args: cflags,
    link_args: ldflags,
)

###############################
##           mjson           ##
###############################

mjson_inc = include_directories(
    'mjson/src/'
)

mjson = static_library(
    'mjson',
    'mjson/src/mjson.c',
    include_directories: mjson_inc,
    c_args: cflags + ['-Wno-unused-but-set-variable'],
    link_args: ldflags,
)

###############################
##            STB            ##
###############################

stb_inc = include_directories(
    'stb/'
)

###############################
##            NFDe           ##
###############################

nfde_inc = include_directories(
    'nfde/src/include/'
)

nfde_src = []
nfde_dep = []

if host_machine.system() == 'windows'
    nfde_src += ['nfde/src/nfd_win.cpp']
elif host_machine.system() == 'darwin'
    add_languages('objc')
    nfde_src += ['nfde/src/nfd_cocoa.m']
    nfde_dep += [
        dependency('appleframeworks', required: true, modules: ['AppKit', 'UniformTypeIdentifiers']),
    ]
else
    nfde_src += ['nfde/src/nfd_gtk.cpp']
    nfde_dep += [
        dependency('gtk+-3.0', required: true, static: static_dependencies),
    ]
endif

nfde = static_library(
    'nfde',
    nfde_src,
    include_directories: nfde_inc,
    dependencies: nfde_dep,
    c_args: cflags,
    cpp_args: cflags,
    link_args: ldflags,
)

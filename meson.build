################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021 - The Hades Authors
##
################################################################################

project(
    'Hades',
    'c',
    'cpp',
    version: '0.0.1',
    license: 'GPL-2.0-only',
    default_options: ['c_std=gnu17', 'buildtype=release'],
)

incdir = include_directories('include', 'source')
cflags = ['-fms-extensions']
ldflags = []

if get_option('static_executable')
    cflags += ['-static']
    ldflags += ['-static']
endif

common_files = files(
    join_paths(meson.current_source_dir(), 'source/common/utils.c'),
)

###############################
## GBA Emulator Core Library ##
###############################

subdir('source/gba')

##############################
## Graphical User Interface ##
##############################

subdir('source/platform/gui')

########################
## Hades Final Binary
########################

custom_target(
    'hades',
    output : 'hades',
    input : hades,
    command : ['cp', '@INPUT@', '@OUTPUT@'],
    install : true,
    install_dir : 'subdir',
)
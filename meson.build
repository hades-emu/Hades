################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2020 - The Hades Authors
##
################################################################################

project('Hades', 'c')

executable(
    'hades',
    'source/core/branch.c',
    'source/core/core.c',
    'source/core/data.c',
    'source/core/mem.c',
    'source/core/sdt.c',
    'source/main.c',
    dependencies: dependency('capstone', version: '>=3.0.0', required: true),
    include_directories: include_directories('include')
)

################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2020 - The Hades Authors
##
################################################################################

project(
    'Hades',
    'c',
    version: '0.0.1',
    default_options: ['c_std=gnu11'],
)

executable(
    'hades',
    'source/core/arm/branch.c',
    'source/core/arm/alu.c',
    'source/core/arm/mul.c',
    'source/core/arm/psr.c',
    'source/core/arm/sdt.c',
    'source/core/thumb/alu.c',
    'source/core/thumb/branch.c',
    'source/core/thumb/loadstore.c',
    'source/core/thumb/logical.c',
    'source/core/bus.c',
    'source/core/core.c',
    'source/debugger/cmd/context.c',
    'source/debugger/cmd/continue.c',
    'source/debugger/cmd/disas.c',
    'source/debugger/cmd/help.c',
    'source/debugger/cmd/next.c',
    'source/debugger/cmd/print.c',
    'source/debugger/cmd/registers.c',
    'source/debugger/cmd/set.c',
    'source/debugger/cmd/step.c',
    'source/debugger/debugger.c',
    'source/rom/rom.c',
    'source/main.c',
    'source/utils.c',
    dependencies: [
        dependency('capstone', version: '>=3.0.0', required: true),
        dependency('readline', version: '>=7', required: true),
    ],
    include_directories: include_directories('include'),
)

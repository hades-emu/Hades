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
    'source/core/arm/alu.c',
    'source/core/arm/bdt.c',
    'source/core/arm/branch.c',
    'source/core/arm/sdt.c',
    'source/core/arm/core.c',
    'source/core/arm/mul.c',
    'source/core/arm/psr.c',
    'source/core/arm/swi.c',
    'source/core/arm/swp.c',
    'source/core/thumb/alu.c',
    'source/core/thumb/branch.c',
    'source/core/thumb/core.c',
    'source/core/thumb/logical.c',
    'source/core/thumb/sdt.c',
    'source/core/thumb/swi.c',
    'source/core/core.c',
    'source/debugger/cmd/break.c',
    'source/debugger/cmd/context.c',
    'source/debugger/cmd/continue.c',
    'source/debugger/cmd/disas.c',
    'source/debugger/cmd/frame.c',
    'source/debugger/cmd/help.c',
    'source/debugger/cmd/main.c',
    'source/debugger/cmd/next.c',
    'source/debugger/cmd/print.c',
    'source/debugger/cmd/registers.c',
    'source/debugger/cmd/set.c',
    'source/debugger/cmd/step.c',
    'source/debugger/cmd/trace.c',
    'source/debugger/cmd/verbose.c',
    'source/debugger/debugger.c',
    'source/memory/dma.c',
    'source/memory/io.c',
    'source/memory/memory.c',
    'source/memory/rom.c',
    'source/platform/sdl.c',
    'source/ppu/oam.c',
    'source/ppu/background.c',
    'source/ppu/ppu.c',
    'source/main.c',
    'source/save.c',
    'source/scheduler.c',
    'source/timer.c',
    'source/utils.c',
    dependencies: [
        dependency('capstone', version: '>=3.0.0', required: true),
        dependency('readline', version: '>=7', required: true),
        dependency('sdl2', version: '>=2', required: true),
        dependency('SDL2_image', version: '>=2', required: true),
        dependency('threads', required: true)
    ],
    include_directories: include_directories('include'),
)

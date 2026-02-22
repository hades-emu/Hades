################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2026 - The Hades Authors
##
################################################################################

libgba_sources = [
    'apu/apu.c',
    'apu/fifo.c',
    'apu/modules.c',
    'apu/noise.c',
    'apu/tone.c',
    'apu/wave.c',
    'core/arm/alu.c',
    'core/arm/bdt.c',
    'core/arm/branch.c',
    'core/arm/sdt.c',
    'core/arm/core.c',
    'core/arm/mul.c',
    'core/arm/psr.c',
    'core/arm/swi.c',
    'core/arm/swp.c',
    'core/thumb/alu.c',
    'core/thumb/bdt.c',
    'core/thumb/branch.c',
    'core/thumb/core.c',
    'core/thumb/logical.c',
    'core/thumb/sdt.c',
    'core/thumb/swi.c',
    'core/core.c',
    'gpio/gpio.c',
    'gpio/rtc.c',
    'gpio/rumble.c',
    'memory/storage/eeprom.c',
    'memory/storage/flash.c',
    'memory/storage/storage.c',
    'memory/bus.c',
    'memory/dma.c',
    'memory/io.c',
    'memory/memory.c',
    'ppu/background/affine.c',
    'ppu/background/bitmap.c',
    'ppu/background/text.c',
    'ppu/oam.c',
    'ppu/ppu.c',
    'ppu/window.c',
    'channel.c',
    'db.c',
    'debugger.c',
    'gba.c',
    'quicksave.c',
    'scheduler.c',
    'timer.c',
]

libgba = static_library(
    'libgba',
    libgba_sources,
    include_directories: incdir,
    dependencies: [
        cc.find_library('m', required: true, static: static_dependencies),
    ],
    c_args: cflags,
    link_args: ldflags,
)

if get_option('with_debugger')
    libgba_dbg = static_library(
        'libgba_dbg',
        libgba_sources,
        include_directories: incdir,
        dependencies: [
            cc.find_library('m', required: true, static: static_dependencies),
        ],
        c_args: cflags + debugger_cflags,
        link_args: ldflags + debugger_ldflags,
    )
endif

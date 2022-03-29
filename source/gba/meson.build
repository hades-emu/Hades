################################################################################
##
##  This file is part of the Hades GBA Emulator, and is made available under
##  the terms of the GNU General Public License version 2.
##
##  Copyright (C) 2021-2022 - The Hades Authors
##
################################################################################

libgba = static_library(
    'gba',
    'apu/apu.c',
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
    'memory/storage/eeprom.c',
    'memory/storage/flash.c',
    'memory/storage/storage.c',
    'memory/dma.c',
    'memory/io.c',
    'memory/memory.c',
    'ppu/background/affine.c',
    'ppu/background/bitmap.c',
    'ppu/background/text.c',
    'ppu/oam.c',
    'ppu/ppu.c',
    'ppu/window.c',
    'db.c',
    'gba.c',
    'quicksave.c',
    'scheduler.c',
    'timer.c',
    include_directories: incdir,
    link_with: libcommon,
    c_args: cflags,
    link_args: ldflags,
)
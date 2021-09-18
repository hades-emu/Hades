cmake_minimum_required(VERSION 3.10)

project(gba, C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "-fms-extensions")

include_directories("${CMAKE_SOURCE_DIR}/include/")

add_library(gba STATIC
    core/arm/alu.c
    core/arm/bdt.c
    core/arm/branch.c
    core/arm/sdt.c
    core/arm/core.c
    core/arm/mul.c
    core/arm/psr.c
    core/arm/swi.c
    core/arm/swp.c
    core/thumb/alu.c
    core/thumb/bdt.c
    core/thumb/branch.c
    core/thumb/core.c
    core/thumb/logical.c
    core/thumb/sdt.c
    core/thumb/swi.c
    core/core.c
    memory/storage/flash.c
    memory/storage/storage.c
    memory/dma.c
    memory/io.c
    memory/memory.c
    ppu/background/affine.c
    ppu/background/bitmap.c
    ppu/background/text.c
    ppu/oam.c
    ppu/ppu.c
    ppu/window.c
    gba.c
    quicksave.c
    scheduler.c
    timer.c
)

target_link_libraries(gba common)
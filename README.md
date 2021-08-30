# 🔥 Hades

![license](https://img.shields.io/github/license/arignir/hades)
[![CodeFactor](https://www.codefactor.io/repository/github/arignir/hades/badge/master)](https://www.codefactor.io/repository/github/arignir/hades/overview/master)
[![Build](https://github.com/Arignir/Hades/actions/workflows/main.yml/badge.svg)](https://github.com/Arignir/Hades/actions/workflows/main.yml)

*A Nintendo Game Boy Advance emulator.*

![](https://i.imgur.com/rC1ToLf.png)

## Download

Hades is still under heavy development, but you can download the latest nightly build for your favorite operating system [here](https://nightly.link/Arignir/Hades/workflows/main/master).

## Run

You need a game ROM and a legitimate GameBoy Advance BIOS or a [replacement BIOS](https://github.com/Cult-of-GBA/BIOS/blob/master/bios.bin).

Move your BIOS to the same folder than Hades and name it `bios.bin`.

You can now either drag and drop your GBA rom over `hades.exe` (Windows only) or open a terminal and run:

```bash
hades <path/to/game.gba>
```

**Usage:**

```
Usage: ./hades [OPTION]... ROM
Options:
        --headless                    disable any graphical output
        --scale=SIZE                  scale the window size by SIZE (default: 3)
        --speed=SPEED                 bind the emulator's FPS to 60*SPEED. 0 means unbounded. (default: 1)
        --color=[always|never|auto]   adjust color settings (default: auto)

    -h, --help                        print this help and exit
        --version                     print the version information and exit
```

## Build

The build dependencies are:

  - `meson`
  - `ninja`
  - `SDL2` and `SDL2_Image`
  - `GCC`

On Ubuntu, you can install all those dependencies with:

```bash
$ apt install meson ninja-build gcc libsdl2-dev libsdl2-image-dev
```

To build Hades, run:

```bash
meson build
cd build
ninja
```

## Thanks

Special thanks to some invaluable resources while writing Hades:

  - [GBATEK](https://problemkaputt.de/gbatek.htm) by Martin Korth
  - [NanoBoyAdvance](https://github.com/fleroviux/NanoBoyAdvance/) by Fleroviux
  - [Cowbite](https://www.cs.rit.edu/~tjh8300/CowBite/CowBiteSpec.htm) by Tom Happ
  - [mGBA](https://mgba.io/) and [mgba-emu/suite](https://github.com/mgba-emu/suite) by Endrift
  - [gba-tests](https://github.com/jsmolka/gba-tests) by Jsmolka
  - [gdkGBA](https://github.com/gdkchan/gdkGBA/) by gdkChan
  - [Tonc](https://www.coranac.com/tonc/text/toc.htm) by Cearn
  - [GBA Cartridge Backup Storage](https://dillonbeliveau.com/2020/06/05/GBA-FLASH.html) by Dillon Beliveau
  - [The Blender model](https://www.blendswap.com/blend/27357) used in this README by Zap Productions

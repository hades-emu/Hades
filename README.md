# 🔥 Hades

![license](https://img.shields.io/github/license/arignir/hades)
[![CodeFactor](https://www.codefactor.io/repository/github/arignir/hades/badge/master)](https://www.codefactor.io/repository/github/arignir/hades/overview/master)
[![Build](https://github.com/Arignir/Hades/actions/workflows/main.yml/badge.svg)](https://github.com/Arignir/Hades/actions/workflows/main.yml)

<p align="center"><img src="https://i.imgur.com/0SJmUXA.png"></p>
<p align="center"><i>A Nintendo Game Boy Advance emulator.</i></p>

## Download

Hades is still under heavy development, but you can download the latest nightly build for your favorite operating system [here](https://nightly.link/Arignir/Hades/workflows/main/master).

## Run

You need a game ROM and a legitimate GameBoy Advance BIOS or a [replacement BIOS](https://github.com/Cult-of-GBA/BIOS/blob/master/bios.bin).

Sart Hades, then click on `File` -> `Open BIOS` and select the BIOS you downloaded above.

You can now play all your favorite games! Click on `File` -> `Open` and select the ROM you want to run.

Alternatively, you can also drag and drop your GBA rom over `hades.exe` (Windows only).

## Build

The build dependencies are:

  - `meson`
  - `ninja`
  - `GCC`
  - `SDL2` and `SDL2_Image`
  - `OpenGL`
  - `glew`

On Ubuntu, you can install all those dependencies with:

```bash
$ apt install meson ninja-build gcc libsdl2-dev libsdl2-image-dev libglew-dev
```

To build Hades, run:

```bash
git submodule update --init --recursive
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

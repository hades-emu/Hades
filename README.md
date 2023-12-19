# 🔥 Hades

![license](https://img.shields.io/github/license/arignir/hades)
[![Build](https://github.com/Arignir/Hades/actions/workflows/build.yml/badge.svg)](https://github.com/Arignir/Hades/actions/workflows/build.yml)

<p align="center"><img src="https://i.imgur.com/4OrVpX2.png"></p>
<p align="center"><i>A Nintendo Game Boy Advance Emulator</i></p>

## Screenshots

<p align="center">
  <img src="https://i.imgur.com/29JPzmU.png">
  <img src="https://i.imgur.com/kyEfEam.png">
  <img src="https://i.imgur.com/c84TjGW.png">
</p>
<p align="center">
  <img src="https://i.imgur.com/WGCHWJv.png">
  <img src="https://i.imgur.com/0LMmkRD.png">
  <img src="https://i.imgur.com/pbdR5AN.png">
</p>

## Features

Hades is still under heavy development but it aims to have a decent balance between usability, speed and accuracy.

Currently, Hades features:
  - Decent accuracy
  - Game controller support
  - Keys and buttons remapping
  - Quick Saves (also known as Save State)
  - Real Time Clock (RTC) support
  - Color correction & LCD effects

It is the third 🥉 software emulator to pass the AGS Aging Cartridge used to test Game Boy Advance systems.

## Run

You can download the latest nightly build for your favorite operating system [here](https://nightly.link/Arignir/Hades/workflows/main/master).

You need a game ROM and a legitimate GameBoy Advance BIOS or a [replacement BIOS](https://github.com/Cult-of-GBA/BIOS/blob/master/bios.bin).

Start Hades, then click on `File` -> `Open BIOS` and select the BIOS (`bios.bin`) you downloaded above.

You can now play all your favorite games! Click on `File` -> `Open` and select the ROM (`<game>.gba`) you want to run.

Alternatively, you can also drag and drop your GBA rom over `hades.exe` (Windows only).

## Build

The build dependencies are:

  - `meson`
  - `ninja`
  - `GCC`
  - `SDL2`
  - `OpenGL`
  - `glew`
  - `gtk3`

On Ubuntu, you can install all those dependencies with:

```bash
$ apt install meson ninja-build gcc libsdl2-dev libglew-dev libgtk-3-dev
```

On Fedora, you can install all those dependencies with:

```bash
$ dnf install meson ninja-build gcc SDL2-devel glew-devel gtk3-devel
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
  - [gba-tests](https://github.com/jsmolka/gba-tests) by Jsmolka
  - [Cowbite](https://www.cs.rit.edu/~tjh8300/CowBite/CowBiteSpec.htm) by Tom Happ
  - [mGBA](https://mgba.io/) and [mgba-emu/suite](https://github.com/mgba-emu/suite) by Endrift
  - [gdkGBA](https://github.com/gdkchan/gdkGBA/) by gdkChan
  - [Tonc](https://www.coranac.com/tonc/text/toc.htm) by Cearn
  - [GBA Cartridge Backup Storage](https://dillonbeliveau.com/2020/06/05/GBA-FLASH.html) by Dillon Beliveau
  - [EEPROM Save Type](https://densinh.github.io/DenSinH/emulation/2021/02/01/gba-eeprom.html) by Dennis H
  - [Explaining GBA Real-Time Clock (RTC)](https://beanmachine.alt.icu/post/rtc/) by Zayd
  - [Higan](https://near.sh/articles/video/color-emulation) for their color correction algorithm (by Talarubi and Near)
  - [The Hades Icon](https://totushi.com/) by Totushi

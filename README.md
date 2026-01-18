# 🔥 Hades

![license](https://img.shields.io/github/license/hades-emu/hades)
[![Build](https://github.com/hades-emu/hades/actions/workflows/build.yml/badge.svg)](https://github.com/hades-emu/hades/actions/workflows/build.yml)
[![Discord](https://img.shields.io/discord/1380316885979234424?label=discord&logo=discord&color=%235865F2)](https://discord.com/invite/zBHkV836AK)

<p align="center"><a href="https://hades-emu.org/"><img src="https://i.imgur.com/4OrVpX2.png"></a></p>
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
  - Some GPIO devices, such as:
    - Real Time Clock (RTC)
    - Rumble
  - Color correction & LCD effects
  - Loading games from common archive formats (`.zip`, `.7z`, `.rar`, etc.)

It is the third 🥉 software emulator to pass the AGS Aging Cartridge used to test Game Boy Advance systems.

## Installation

Follow the instructions on our [official website](https://hades-emu.org/download) to download and install Hades the latest release of Hades.

## Build

To build Hades, you first need to install those dependencies:

  - `meson`
  - `ninja`
  - `GCC`
  - `SDL3`
  - `OpenGL`
  - `glew`
  - `libarchive`

On the latest Ubuntu, you can install all those dependencies with:

```bash
$ apt install meson ninja-build gcc libsdl3-dev libglew-dev libarchive-dev
```

On Fedora, you can install all those dependencies with:

```bash
$ dnf install meson ninja-build gcc SDL3-devel glew-devel libarchive-devel
```

Finally, to build Hades, run:

```bash
git submodule update --init --recursive
meson build
cd build
ninja
```

## Thanks

Special thanks to some invaluable individuals and resources while writing Hades:

  - [GBATEK](https://problemkaputt.de/gbatek.htm) by Martin Korth
  - [NanoBoyAdvance](https://github.com/fleroviux/NanoBoyAdvance/) by Fleroviux
  - [mGBA](https://mgba.io/) and [mgba-emu/suite](https://github.com/mgba-emu/suite) by Endrift
  - [gba-tests](https://github.com/jsmolka/gba-tests) by Jsmolka
  - [Cowbite](https://www.cs.rit.edu/~tjh8300/CowBite/CowBiteSpec.htm) by Tom Happ
  - [gdkGBA](https://github.com/gdkchan/gdkGBA/) by gdkChan
  - [Tonc](https://www.coranac.com/tonc/text/toc.htm) by Cearn
  - [GBA Cartridge Backup Storage](https://dillonbeliveau.com/2020/06/05/GBA-FLASH.html) by Dillon Beliveau
  - [EEPROM Save Type](https://densinh.github.io/DenSinH/emulation/2021/02/01/gba-eeprom.html) by Dennis H
  - [Explaining GBA Real-Time Clock (RTC)](https://beanmachine.alt.icu/post/rtc/) by Zayd
  - [Higan](https://near.sh/articles/video/color-emulation) for their color correction algorithm (by Talarubi and Near)
  - [The Hades Icon](https://totushi.com/) by Totushi

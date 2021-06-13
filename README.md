# :fire: Hades

A GBA emulator,

This project is under heavy development and can't properly run any game yet.

## Building

To build Hades, you need:
  - `meson`
  - `ninja`
  - `SDL2`
  - `readline`
  - `capstone`

On Ubuntu, you can install all the dependecies by running:

```bash
$ apt install meson ninja-build libsdl2-dev libreadline-dev libcapstone-dev
```

To build the project, run:

```bash
meson build --buildtype=release
cd build
ninja
```

To run Hades, you need a game ROM and a legitimate GameBoy Advance BIOS or a replacement BIOS.

Place your BIOS in the same folder than the executable and name it `gba_bios.gba`.

You can then run:

```bash
hades <path/to/game.gba>
```

## Thanks

Special thanks to some insanely good reading/projects that act as a documentation when writing this project:

  - [GBATEK](https://problemkaputt.de/gbatek.htm)
  - [Tonc](https://www.coranac.com/tonc/text/toc.htm)
  - [gba-tests](https://github.com/jsmolka/gba-tests)
  - [NanoBoyAdvance](https://github.com/fleroviux/NanoBoyAdvance/)
  - [mGBA](https://mgba.io/)
  - [gdkGBA](https://github.com/gdkchan/gdkGBA/)

# 🔥 Hades

A Nintendo Game Boy Advance emulator.

![](https://i.imgur.com/vO1sDOV.png)

## Running

You need a game ROM and a legitimate GameBoy Advance BIOS or a replacement BIOS.

Place your BIOS in the same folder than the executable and name it `bios.bin`.

You can then run:

```bash
hades <path/to/game.gba>
```

**Usage:**

```
Usage: ./hades [OPTION]... ROM
Options:
    -d, --debugger                    enable the debugger
        --headless                    use Hades without any graphical output
    -s, --scale=SIZE                  scale the window by SIZE
        --color=[always|never|auto]   adjust color settings (default: auto)

    -h, --help                        print this help and exit
        --version                     print the version information and exit
```

## Building

The build dependencies are:

  - `meson`
  - `ninja`
  - `SDL2` and `SDL2_Image`
  - `GCC`
  - `readline`
  - `capstone`

On Ubuntu, you can install all those dependencies with:

```bash
$ apt install meson ninja-build gcc libsdl2-dev libsdl2-image-dev libreadline-dev libcapstone-dev
```

To build Hades, run:

```bash
meson build
cd build
ninja
```

## Thanks

Special thanks to some insanely good reading/projects that act as documentation when writing Hades:

  - [GBATEK](https://problemkaputt.de/gbatek.htm)
  - [Tonc](https://www.coranac.com/tonc/text/toc.htm)
  - [Cowbite](https://www.cs.rit.edu/~tjh8300/CowBite/CowBiteSpec.htm)
  - [gba-tests](https://github.com/jsmolka/gba-tests)
  - [NanoBoyAdvance](https://github.com/fleroviux/NanoBoyAdvance/)
  - [gdkGBA](https://github.com/gdkchan/gdkGBA/)
  - [mGBA](https://mgba.io/)

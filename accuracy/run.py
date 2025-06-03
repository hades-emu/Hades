#!/usr/bin/env python3

import os
import shutil
import textwrap
import argparse
import subprocess
import tempfile
from pathlib import Path
from test import TestResult


GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
BOLD = '\033[1m'
RESET = '\033[0m'


def main():
    from suite import TESTS_SUITE

    exit_code = 0

    parser = argparse.ArgumentParser(
        prog='Hades Accuracy Checker',
        description='Tests the accuracy of Hades, a GameBoy Advance Emulator',
    )

    parser.add_argument(
        '--binary',
        nargs='?',
        default='./hades-dbg',
        help="Path to Hades' binary",
    )

    parser.add_argument(
        '--bios',
        nargs='?',
        default='./bios.bin',
        help="Path to the BIOS",
    )

    parser.add_argument(
        '--roms',
        nargs='?',
        default='./roms',
        help="Path to the test ROMS folder",
    )

    parser.add_argument(
        '--download',
        '-d',
        action='store_true',
        help="Download the available test ROMS",
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help="Show subcommands output",
    )

    args = parser.parse_args()

    hades_binary: Path = Path(os.getcwd()) / args.binary
    bios: Path = Path(os.getcwd()) / args.bios
    rom_directory: Path = Path(os.getcwd()) / args.roms

    if not hades_binary.exists():
        print(f"Error: {hades_binary}: no such file or directory.")
        exit(1)

    if not bios.exists():
        print(f"Error: {bios}: no such file or directory.")
        exit(1)

    for test in TESTS_SUITE:
        if not test.rom.path(rom_directory).exists():
            if args.download:
                try:
                    if test.rom.url is None:
                        print(f"Skipping test \"{test.name}\" because ROM \"{test.rom.filename}\" is missing from the ROM directory.")
                        test.skip = True
                        continue

                    print(f"Downloading test rom \"{test.rom.filename}\".")
                    test.rom.download(rom_directory)
                except RuntimeError as e:
                    print(f"An error occurred while downloading {test.rom.filename}: {e}")
            else:
                print(f"Skipping test \"{test.name}\" because ROM \"{test.rom.filename}\" is missing from the ROM directory. Try downloading it using the \"--download\" flag.")
                test.skip = True

    # Ensure Hades was built with its debugger
    try:
        subprocess.run(
            [hades_binary, '--without-gui', '--help'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding='utf-8',
            check=True,
        )
    except subprocess.CalledProcessError:
        print("Error: Hades wasn't build with its debugger.")
        exit(1)

    config = tempfile.NamedTemporaryFile()
    config.write(textwrap.dedent(f'''
        {{
          "file": {{
            "bios": "{bios}"
          }},
          "emulation": {{
            "pause_when_game_resets": true,
            "skip_bios": true,
            "speed": 0,
            "fast_forward": true,
            "prefetch_buffer": true,
            "backup_storage": {{
              "autodetect": true,
              "type": 0
            }},
            "gpio": {{
              "autodetect": true,
              "type": 0
            }}
          }},
        }}
    ''').encode('utf-8'))
    config.flush()

    tests_screenshots_directory = Path(os.getcwd()) / '.tests_screenshots'
    if tests_screenshots_directory.exists():
        shutil.rmtree(tests_screenshots_directory)
    os.mkdir(tests_screenshots_directory)

    print(f"┏━{'━' * 34}━┳━━━━━━┓")
    print(f"┃ {'Name':34s} ┃ Res. ┃")
    print(f"┣━{'━' * 34}━╋━━━━━━┫")

    for test in TESTS_SUITE:
        result = TestResult.FAIL

        try:
            if test.skip:
                result = TestResult.SKIP
                continue

            test.run(hades_binary, rom_directory, Path(config.name), tests_screenshots_directory, args.verbose)
            result = TestResult.PASS
        except Exception as e:
            if args.verbose:
                print(f"Error: {e}")
            result = TestResult.FAIL
        finally:
            if result == TestResult.PASS:
                pretty_result = f'{BOLD}{GREEN}PASS{RESET}'
            elif result == TestResult.SKIP:
                pretty_result = f'{BOLD}{YELLOW}SKIP{RESET}'
            else:
                pretty_result = f'{BOLD}{RED}FAIL{RESET}'
                exit_code = 1

            print(f"┃ {test.name:34s} ┃ {pretty_result} ┃")

    print(f"┗━{'━' * 34}━┻━━━━━━┛")

    exit(exit_code)


if __name__ == '__main__':
    main()

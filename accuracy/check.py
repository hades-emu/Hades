#!/usr/bin/env python3

import os
import shutil
import filecmp
import textwrap
import argparse
import subprocess
import tempfile
from enum import Enum
from pathlib import Path


GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
BOLD = '\033[1m'
RESET = '\033[0m'


class TestResult(Enum):
    PASS = 0
    SKIP = 1
    FAIL = 2


class Test():
    def __init__(self, name: str, rom: str, code: str, screenshot: str, skip: bool = False):
        self.name = name

        self.rom = rom
        self.code = textwrap.dedent(code)
        self.screenshot = screenshot
        self.skip = skip

    def run(self, hades_path: Path, rom_directory: Path, config_path: Path, tests_screenshots_directory: Path, verbose: bool):
        module_path = Path(os.path.realpath(__file__)).parent

        subprocess.run(
            [hades_path, rom_directory / self.rom, '--without-gui', '--config', config_path],
            input=self.code,
            stdout=None if verbose else subprocess.DEVNULL,
            stderr=None if verbose else subprocess.DEVNULL,
            text=True,
            encoding='utf-8',
            check=True,
        )

        if not filecmp.cmp(tests_screenshots_directory / self.screenshot, module_path / 'expected' / self.screenshot, shallow=False):
            raise RuntimeError("The screenshot taken during the test doesn't match the expected one.")


def main():
    from suite import TESTS_SUITE

    exit_code = 0

    parser = argparse.ArgumentParser(
        prog='Hades Accuracy Checker',
        description='Tests the accuracy of Hades, a Gameboy Advance Emulator',
    )

    parser.add_argument(
        '--binary',
        nargs='?',
        default='./hades',
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
        if not (rom_directory / test.rom).exists():
            print(f"Skipping test \"{test.name}\" because ROM {test.rom} is missing from the ROM directory.")
            test.skip = True

    # Ensure Hades is built with the debugger
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
            "skip_bios": true,
            "pause_on_reset": true,
            "speed": 1,
            "fast_forward": true,
            "backup_storage": {{
              "autodetect": true,
              "type": 0
            }},
            "gpio": {{
              "autodetect": true,
              "type": 0
            }}
          }}
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

            test.run(hades_binary, rom_directory, config.name, tests_screenshots_directory, args.verbose)
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

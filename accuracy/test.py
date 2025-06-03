import filecmp
import os
import subprocess
import textwrap
from enum import Enum
from pathlib import Path

from rom import Rom


class TestResult(Enum):
    PASS = 0
    SKIP = 1
    FAIL = 2


class Test:
    def __init__(self, name: str, rom: Rom, code: str, screenshot: str, skip: bool = False):
        self.name = name

        self.rom = rom
        self.code = textwrap.dedent(code)
        self.screenshot = screenshot
        self.skip = skip

    def run(self, hades_path: Path, rom_directory: Path, config_path: Path, tests_screenshots_directory: Path, verbose: bool):
        module_path = Path(os.path.realpath(__file__)).parent

        subprocess.run(
            [hades_path, self.rom.path(rom_directory), '--without-gui', '--config', config_path],
            input=self.code,
            stdout=None if verbose else subprocess.DEVNULL,
            stderr=None if verbose else subprocess.DEVNULL,
            text=True,
            encoding='utf-8',
            check=True,
        )

        if not filecmp.cmp(tests_screenshots_directory / self.screenshot, module_path / 'expected' / self.screenshot, shallow=False):
            raise RuntimeError("The screenshot taken during the test doesn't match the expected one.")

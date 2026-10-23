import filecmp
import os
import subprocess
import textwrap
from enum import Enum
from typing import List
from pathlib import Path

from rom import Rom
from cheat import Cheat


class TestResult(Enum):
    PASS = 0
    SKIP = 1
    FAIL = 2


class Test:
    def __init__(self, name: str, rom: Rom, code: str, screenshots: List[str], cheats: List[Cheat] = [], skip_all: bool = False, skip: List[int] = []):
        self.name = name

        self.rom = rom
        self.cheats = cheats
        self.code = textwrap.dedent(code)
        self.screenshots = screenshots
        self.skip_all = skip_all
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

        results = []

        for i, screenshot in enumerate(self.screenshots):
            if i + 1 in self.skip:
                results += [TestResult.SKIP]
                continue

            if filecmp.cmp(tests_screenshots_directory / screenshot, module_path / 'expected' / screenshot, shallow=False):
                results += [TestResult.PASS]
            else:
                results += [TestResult.FAIL]

        return results

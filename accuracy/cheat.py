import os
import json
import shutil
from enum import Enum
from typing import List
from pathlib import Path
import urllib.request


class CheatKind(Enum):
    # Must match `RAW_CHEAT_KIND_*` in `include/gba/gba.h`
    PARV3 = 0
    GAMESHARK = 1
    CODEBREAKER = 2


class Cheat:
    def __init__(self, name: str, kind: CheatKind, url: str):
        self.name = name
        self.filename = name + '.hex'
        self.kind = kind
        self.url = url

    def path(self, rom_directory: Path) -> Path:
        return rom_directory / self.filename

    def download(self, rom_directory: Path):
        os.makedirs(rom_directory, exist_ok=True)

        with urllib.request.urlopen(self.url) as response:
            with open(self.path(rom_directory), 'wb') as out_file:
                shutil.copyfileobj(response, out_file)


def write_cheats_file(cheats: List[Cheat], rom_path: Path, rom_directory: Path):
    entries = []

    for cheat in cheats:
        with open(cheat.path(rom_directory), 'r', encoding='utf-8') as in_file:
            entries += [{
                'kind': cheat.kind.value,
                'enabled': True,
                'name': cheat.name,
                'code': in_file.read(),
            }]

    with open(rom_path.with_suffix('.cheats.json'), 'w', encoding='utf-8') as out_file:
        json.dump(entries, out_file, indent=2)

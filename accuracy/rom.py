import io
import os
import shutil
import zipfile
from pathlib import Path
import urllib.request


class Rom:
    def __init__(self, name: str, url: str | None):
        self.name = name
        self.filename = name + '.gba'
        self.url = url

    def path(self, rom_directory: Path) -> Path:
        return rom_directory / self.filename

    def download(self, rom_directory: Path):
        os.makedirs(rom_directory, exist_ok=True)

        with urllib.request.urlopen(self.url) as response:
            if self.url.endswith('.zip'):
                with zipfile.ZipFile(io.BytesIO(response.read()), 'r') as zip_file:
                    files = zip_file.namelist()

                    if len(files) != 1:
                        raise RuntimeError("Multiple files in the download ZIP file")

                    with zip_file.open(files[0]) as zip_inner_file:
                        with open(self.path(rom_directory), 'wb') as out_file:
                            shutil.copyfileobj(zip_inner_file, out_file)
            else:
                with open(self.path(rom_directory), 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)

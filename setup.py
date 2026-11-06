"""Include runtime contracts in wheels without duplicating their source files."""
from pathlib import Path
from shutil import copy2

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithContracts(build_py):
    def run(self):
        super().run()
        root = Path(__file__).parent
        destination = Path(self.build_lib) / "harbor_pipeline" / "resources"
        for directory, pattern in (("schemas", "*.json"), ("policies", "*.toml"), ("docs/reference", "*.json")):
            target = destination / Path(directory).name
            target.mkdir(parents=True, exist_ok=True)
            for source in (root / directory).glob(pattern):
                copy2(source, target / source.name)


setup(cmdclass={"build_py": BuildWithContracts})

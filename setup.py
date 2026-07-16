from __future__ import annotations

import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist

PACKAGE = "factoryline"


def source_commit() -> str | None:
    root = Path(__file__).resolve().parent
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except OSError:
        return None
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and len(commit) == 40 else None


def write_provenance(path: Path, commit: str | None) -> None:
    path.write_text(
        '"""Generated build provenance. Do not edit.\n\n'
        "This file is rewritten while creating source distributions from a Git checkout.\n"
        '"""\n\n'
        f"SOURCE_COMMIT = {commit!r}\n",
        encoding="utf-8",
    )


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        commit = source_commit()
        if commit:
            write_provenance(Path(self.build_lib) / PACKAGE / "_build_provenance.py", commit)


class sdist(_sdist):
    def make_release_tree(self, base_dir: str, files: list[str]) -> None:
        super().make_release_tree(base_dir, files)
        write_provenance(Path(base_dir) / PACKAGE / "_build_provenance.py", source_commit())


setup(cmdclass={"build_py": build_py, "sdist": sdist})

from __future__ import annotations

import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel

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
    path.parent.mkdir(parents=True, exist_ok=True)
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
            write_provenance(
                Path(self.build_lib) / PACKAGE / "_build_provenance.py", commit
            )


class sdist(_sdist):
    def make_release_tree(self, base_dir: str, files: list[str]) -> None:
        super().make_release_tree(base_dir, files)
        write_provenance(
            Path(base_dir) / PACKAGE / "_build_provenance.py", source_commit()
        )


class bdist_wheel(_bdist_wheel):
    def run(self) -> None:
        """Never resurrect deleted source or data from previous build outputs."""
        with TemporaryDirectory(prefix="factoryline-wheel-") as scratch:
            command = self.reinitialize_command("build", reinit_subcommands=True)
            command.build_base = str(Path(scratch) / "build")
            for option in (
                "build_lib",
                "build_purelib",
                "build_platlib",
                "build_temp",
                "build_scripts",
            ):
                setattr(command, option, None)
            self.bdist_dir = str(Path(scratch) / "wheel")
            self.skip_build = False
            super().run()


setup(cmdclass={"build_py": build_py, "sdist": sdist, "bdist_wheel": bdist_wheel})

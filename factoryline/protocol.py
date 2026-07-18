"""Versioned cross-brick protocol and compatibility checks."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import re
import shutil


RECEIPT_SCHEMA = "factory.receipt.v2"
CHALLENGE_SCHEMA = "factory.challenge.v1"
PASSPORT_SCHEMA = "factory.passport.v1"

MINIMUM_VERSIONS = {
    "specline": "0.5.4",
    "forgeline": "0.10.7",
    "hsf": "0.5.5",
    "prestige": "0.7.4",
}

REQUIRED_COMMANDS = {
    "specline": {"strict", "verify-validators", "challenge"},
    "forgeline": {"gate", "fill", "verify-tests", "challenge"},
    "hsf": {"compile", "goldens", "challenge"},
    "prestige": {"audit", "render-audit", "challenge", "tokens", "verify-tokens", "init", "report", "pr", "ci", "benchmark"},
}


def version_tuple(value: str) -> tuple[int, ...]:
    """Parse the numeric release components from a version for compatibility checks."""
    numbers = re.findall(r"\d+", value)
    return tuple(int(part) for part in numbers[:3]) or (0,)


@dataclass(frozen=True)
class Compatibility:
    module: str
    cli: str
    package: str
    installed: bool
    version: str | None
    minimum: str
    version_ok: bool
    commands_ok: bool | None = None
    missing_commands: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Return whether the installed producer satisfies the required protocol range."""
        return self.installed and self.version_ok and self.commands_ok is not False


def package_version(package: str) -> str | None:
    """Return an installed package version, or None when the package is unavailable."""
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def compatibility(
    module: str,
    meta: dict,
    help_text: str | None = None,
    *,
    reported_version: str | None = None,
) -> Compatibility:
    """Evaluate producer compatibility against explicit minimum and maximum versions."""
    installed = shutil.which(meta["cli"]) is not None
    version = package_version(meta["pip"]) or reported_version
    minimum = MINIMUM_VERSIONS[module]
    required = REQUIRED_COMMANDS[module]
    missing = tuple(sorted(command for command in required if help_text is not None and command not in help_text))
    return Compatibility(
        module=module,
        cli=meta["cli"],
        package=meta["pip"],
        installed=installed,
        version=version,
        minimum=minimum,
        version_ok=version is not None and version_tuple(version) >= version_tuple(minimum),
        commands_ok=None if help_text is None else not missing,
        missing_commands=missing,
    )

"""Create and verify a hash-bound JetBrains Marketplace release candidate."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile


SCHEMA_VERSION = 1
EXPECTED_PLUGIN_ID = "app.factoryline"
TAG_PATTERN = re.compile(
    r"jetbrains-v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z"
)


class ArtifactError(ValueError):
    """Raised when a Marketplace candidate violates the release contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plugin_metadata(archive: Path) -> dict[str, str]:
    if not archive.is_file():
        raise ArtifactError(f"Marketplace archive does not exist: {archive}")
    try:
        with ZipFile(archive) as distribution:
            jars = sorted(
                name
                for name in distribution.namelist()
                if "/lib/" in name and name.endswith(".jar")
            )
            for jar_name in jars:
                with ZipFile(io.BytesIO(distribution.read(jar_name))) as plugin_jar:
                    if "META-INF/plugin.xml" not in plugin_jar.namelist():
                        continue
                    root = ET.fromstring(plugin_jar.read("META-INF/plugin.xml"))
                    plugin_id = (root.findtext("id") or "").strip()
                    version = (root.findtext("version") or "").strip()
                    name = (root.findtext("name") or "").strip()
                    if plugin_id != EXPECTED_PLUGIN_ID:
                        raise ArtifactError(
                            f"Expected plugin id {EXPECTED_PLUGIN_ID!r}, found {plugin_id!r}."
                        )
                    if not version or not name:
                        raise ArtifactError("plugin.xml must contain non-empty name and version values.")
                    return {"id": plugin_id, "name": name, "version": version}
    except (BadZipFile, ET.ParseError, KeyError) as exc:
        raise ArtifactError(f"Invalid JetBrains plugin archive: {exc}") from exc
    raise ArtifactError("No plugin JAR containing META-INF/plugin.xml was found.")


def create_manifest(
    archive: Path, *, release_ref: str, commit: str, channel: str
) -> dict[str, object]:
    """Describe an inspected Marketplace ZIP without including credentials."""
    if not TAG_PATTERN.fullmatch(release_ref):
        raise ArtifactError(
            "release_ref must be a dedicated immutable tag such as jetbrains-v0.7.1."
        )
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ArtifactError("commit must be a full lowercase 40-character Git SHA.")
    if not channel or any(char.isspace() for char in channel):
        raise ArtifactError("channel must be non-empty and contain no whitespace.")
    plugin = _plugin_metadata(archive)
    tagged_version = release_ref.removeprefix("jetbrains-v")
    if plugin["version"] != tagged_version:
        raise ArtifactError(
            f"Release tag version {tagged_version!r} does not match plugin version "
            f"{plugin['version']!r}."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact": {
            "file": archive.name,
            "sha256": _sha256(archive),
            "size": archive.stat().st_size,
        },
        "plugin": plugin,
        "release": {"channel": channel, "commit": commit, "ref": release_ref},
    }


def verify_manifest(
    archive: Path,
    manifest_path: Path,
    *,
    release_ref: str,
    commit: str,
    channel: str,
) -> dict[str, object]:
    """Fail closed unless the candidate still matches its validation receipt."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"Cannot read release manifest: {exc}") from exc
    expected = create_manifest(
        archive, release_ref=release_ref, commit=commit, channel=channel
    )
    if manifest != expected:
        raise ArtifactError("Marketplace artifact manifest does not match the candidate or release inputs.")
    return expected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--archive", type=Path, required=True)
        subparser.add_argument("--manifest", type=Path, required=True)
        subparser.add_argument("--release-ref", required=True)
        subparser.add_argument("--commit", required=True)
        subparser.add_argument("--channel", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the artifact manifest creator or verifier."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_manifest(
                args.archive,
                release_ref=args.release_ref,
                commit=args.commit,
                channel=args.channel,
            )
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            manifest = verify_manifest(
                args.archive,
                args.manifest,
                release_ref=args.release_ref,
                commit=args.commit,
                channel=args.channel,
            )
    except ArtifactError as exc:
        print(f"JetBrains release artifact rejected: {exc}", file=sys.stderr)
        return 1
    print(
        f"Verified {manifest['plugin']['id']} {manifest['plugin']['version']} "
        f"({manifest['artifact']['sha256']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

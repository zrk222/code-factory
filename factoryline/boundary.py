"""Guards that keep build-time learning state out of deterministic artifacts."""
from pathlib import Path

BUILD_TIME_ONLY = {"attribution", "refine", "rejection_ledger", "edit_selection"}


def assert_no_attribution_in_artifact(artifact_path: Path) -> None:
    """Reject generated artifacts that leak build-time learning symbols."""
    source = Path(artifact_path).read_text(encoding="utf-8")
    leaked = sorted(symbol for symbol in BUILD_TIME_ONLY if symbol in source)
    if leaked:
        raise ValueError(f"build-time symbols leaked into artifact: {', '.join(leaked)}")


def assert_build_metadata_locations(root: Path) -> None:
    """Reject build-only metadata files found beneath the runtime registry."""
    registry = Path(root) / "registry"
    if not registry.exists():
        return
    offenders = [
        path for path in registry.rglob("*")
        if path.is_file() and any(token in path.name for token in BUILD_TIME_ONLY)
    ]
    if offenders:
        raise ValueError(f"build metadata found in registry: {offenders}")

"""Guards that keep build-time learning state out of deterministic artifacts."""
from pathlib import Path

BUILD_TIME_ONLY = {"attribution", "refine", "rejection_ledger", "edit_selection"}


def assert_no_attribution_in_artifact(artifact_path: Path) -> None:
    source = Path(artifact_path).read_text(encoding="utf-8")
    leaked = sorted(symbol for symbol in BUILD_TIME_ONLY if symbol in source)
    if leaked:
        raise ValueError(f"build-time symbols leaked into artifact: {', '.join(leaked)}")

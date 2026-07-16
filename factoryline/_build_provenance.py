"""Build provenance fallback for source-tree use.

This file is replaced with the clean Git revision in source distributions and
wheels. A source checkout deliberately carries no claimed release identity.
"""

SOURCE_COMMIT: str | None = None

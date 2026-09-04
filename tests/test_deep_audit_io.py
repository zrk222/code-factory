from pathlib import Path

import pytest

from factoryline.deep_audit_io import local_file
from factoryline.runtime_audit_common import RuntimeAuditError


def test_missing_nested_source_has_typed_error(tmp_path: Path) -> None:
    with pytest.raises(RuntimeAuditError) as exc:
        local_file(tmp_path, "missing/report.json")
    assert exc.value.code == "E_SOURCE_MISSING"

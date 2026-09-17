from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.receipt_index import build_receipt_index


def test_receipt_index_is_content_addressed_and_plan_only(tmp_path: Path) -> None:
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    (receipt_dir / "one.json").write_text('{"ok":true}\n', encoding="utf-8")
    (receipt_dir / "two.json").write_text('{"ok":true}\n', encoding="utf-8")
    result = build_receipt_index(tmp_path, hot_days=0, max_files=1)
    assert result["counts"]["files"] == 2
    assert result["counts"]["over_limit"] == 1
    assert result["counts"]["duplicate_groups"] == 1
    assert result["retention_plan"]["mutation"] is False


def test_receipt_index_cli_writes_local_index(tmp_path: Path, capsys) -> None:
    (tmp_path / "receipts").mkdir()
    (tmp_path / "receipts" / "one.json").write_text('{}', encoding="utf-8")
    assert main(["ops", "receipts", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.receipt-index.v1"
    assert (tmp_path / ".factory" / "ops" / "receipt-index.json").is_file()

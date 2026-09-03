from __future__ import annotations

import json
from pathlib import Path
import sys

from factoryline.runtime_audit_process import run_bounded_command
from factoryline.runtime_audit_runner import run_runtime_audit_plan


def test_runner_uses_exact_argv_separate_artifacts_and_no_worktree_home(tmp_path):
    writer = tmp_path / "writer.py"
    writer.write_text("import json,sys; json.dump({'schema':'fixture','mode':sys.argv[1]},open(sys.argv[2],'w'))\n", encoding="utf-8")
    lane = {"id": "lane", "kind": "stateful_invariant", "timeout_seconds": 5, "target_argv": [sys.executable, str(writer), "target", "{artifact}"], "known_bad_argv": [sys.executable, str(writer), "known_bad", "{artifact}"]}
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path/"out")
    execution = result["executions"][0]
    assert execution["target"]["artifact"]["mode"] == "target"
    assert execution["known_bad"]["artifact"]["mode"] == "known_bad"
    assert execution["target"]["artifact_sha256"] != execution["known_bad"]["artifact_sha256"]
    assert not (tmp_path/".runtime-home").exists()


def test_supervisor_times_out_and_hashes_output_without_retaining_it(tmp_path):
    scratch = tmp_path/"scratch"; scratch.mkdir()
    result = run_bounded_command([sys.executable, "-c", "import time; print('safe'); time.sleep(2)"], tmp_path, 1, scratch)
    assert result["timed_out"] is True
    assert result["cleanup_confirmed"] is True
    assert "safe" not in json.dumps(result)

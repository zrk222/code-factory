from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
import json

import pytest

from factoryline.deep_audit_contract import (
    PLAN_SCHEMA,
    PLAN_TYPE,
    load_execution_manifest,
    verify_deep_audit_plan,
)
from factoryline.deep_audit_io import digest
from factoryline.enterprise_receipts import (
    generate_key_material,
    sign_payload,
    EnterpriseReceiptError,
)
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def test_keyless_review_decodes_lossless_bounded_input():
    import ast
    from base64 import b64encode
    import gzip
    import lzma

    import yaml

    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/deep-audit-keyless-reviewer.yml"
    )
    flow = yaml.load(workflow.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    script = next(
        step["run"]
        for step in flow["jobs"]["analyze"]["steps"]
        if "def decode_review_packet" in step.get("run", "")
    )
    source = script.split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(source)
    tree.body = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
    ]
    scope = {}
    exec(compile(tree, str(workflow), "exec"), scope)
    decode = scope["decode_review_packet"]
    raw = b'{"evidence":"example"}'
    xz = lzma.compress(raw, preset=6)
    assert decode(b64encode(xz)) == decode(b64encode(gzip.compress(raw))) == raw
    for invalid in (xz[:-5], xz + xz):
        with pytest.raises(ValueError, match="one complete XZ stream"):
            decode(b64encode(invalid))
    for compress in (gzip.compress, lzma.compress):
        with pytest.raises(ValueError, match="exceeds the decoded size limit"):
            decode(b64encode(compress(b"a" * 4_194_305)))


@pytest.mark.parametrize("modified", [False, True])
def test_keyless_coordinator_seals_exact_eight_lane_plan(
    tmp_path, monkeypatch, modified
):
    import yaml

    repo = Path(__file__).resolve().parents[1]
    workflow = repo / ".github/workflows/deep-audit-keyless-coordinator.yml"
    flow = yaml.load(workflow.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    step = next(
        item
        for item in flow["jobs"]["authorize"]["steps"]
        if item.get("name")
        == "Bind only the approved candidate to exact role workflows"
    )
    source = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    command = compile(source, str(workflow), "exec")
    plan_path = Path("scripts/deep-audit-keyless-plan.json")
    raw_plan = (repo / plan_path).read_bytes()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", "zrk222/code-factory")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    plan_path.parent.mkdir()
    plan_path.write_bytes(raw_plan + b" " if modified else raw_plan)

    root = Path("control")
    if modified:
        with pytest.raises(ValueError, match="approved SHA-256"):
            exec(command, {})
        assert not root.exists()
        return

    exec(command, {})
    manifest_bytes = (root / "manifest.json").read_bytes()
    manifest = load_execution_manifest(
        root / "manifest.json", sha256_bytes(manifest_bytes)
    )
    assert manifest == json.loads(manifest_bytes)
    payload = json.loads((root / "authorization-payload.json").read_bytes())
    assert len(manifest["lanes"]) == 8 and len(manifest["obligations"]) == 10
    assert len({lane["family"] for lane in manifest["lanes"]}) == 6
    assert manifest["lanes"] == json.loads(raw_plan)["lanes"]
    assert payload["adapter_images"] == {
        lane["id"]: lane["image"] for lane in manifest["lanes"]
    }
    assert (
        payload["manifest_sha256"]
        == payload["manifest_content_sha256"]
        == sha256_bytes(manifest_bytes)
    )
    assert payload["candidate_sha256"] == manifest["candidate_sha256"]
    assert payload["authority"] == "none"


def test_keyless_artifact_download_follows_producing_job_on_rerun():
    import yaml

    workflows = Path(__file__).resolve().parents[1] / ".github/workflows"

    def load(role):
        path = workflows / f"deep-audit-keyless-{role}.yml"
        return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    def artifact_step(job, action):
        return next(
            step
            for step in job["steps"]
            if step.get("uses", "").startswith(f"actions/{action}-artifact@")
        )

    review = load("reviewer")
    jobs = review["jobs"]
    coordinator = load("coordinator")["jobs"]
    for job, prefix in (
        (jobs["assemble"], "keyless-review-model-output"),
        (jobs["sign"], "keyless-specialty-review"),
        (coordinator["authorize"], "keyless-audit-authorization"),
        (coordinator["attest-invocation"], "keyless-review-invocation"),
    ):
        upload = artifact_step(job, "upload")
        assert upload["with"]["name"] == prefix + "-${{ github.run_attempt }}"
        assert upload["with"].get("overwrite", "false") == "false"

    for producer, consumer, output in (
        (jobs["assemble"], jobs["sign"], "${{ needs.assemble.outputs.artifact_id }}"),
        (
            jobs["sign"],
            coordinator["attest-invocation"],
            "${{ needs.reviewer.outputs.signed_review_artifact_id }}",
        ),
    ):
        upload = artifact_step(producer, "upload")
        assert producer["outputs"]["artifact_id"] == (
            "${{ steps." + upload["id"] + ".outputs.artifact-id }}"
        )
        download = artifact_step(consumer, "download")
        guard = consumer["steps"][consumer["steps"].index(download) - 1]
        assert guard["env"]["ARTIFACT_ID"] == output
        assert '[[ "$ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]' in guard["run"]
        assert download["with"]["artifact-ids"] == output
        assert "name" not in download["with"] and "pattern" not in download["with"]

    assert (
        review["on"]["workflow_call"]["outputs"]["signed_review_artifact_id"]["value"]
        == "${{ jobs.sign.outputs.artifact_id }}"
    )


def _keyless_review_fixture():
    from types import ModuleType

    import yaml

    repo = Path(__file__).resolve().parents[1]
    workflow_path = repo / ".github/workflows/deep-audit-keyless-reviewer.yml"
    flow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    step = next(
        item
        for item in flow["jobs"]["analyze"]["steps"]
        if item.get("name") == "Run the read-only specialty inference"
    )
    source = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    review = ModuleType("family_review")
    exec(compile(source, str(workflow_path), "exec"), review.__dict__)
    plan_path = repo / "scripts/deep-audit-keyless-plan.json"
    plan = json.loads(plan_path.read_bytes())
    jobs = flow["jobs"]
    families = set(jobs["analyze"]["strategy"]["matrix"]["family"])
    assert families == {lane["family"] for lane in plan["lanes"]}
    assert jobs["prepare"]["permissions"] == {}
    assert jobs["prepare"]["if"] == jobs["analyze"]["if"]
    assert jobs["prepare"]["runs-on"] == jobs["analyze"]["runs-on"] == "ubuntu-24.04"
    assert jobs["analyze"]["needs"] == "prepare"
    assert jobs["assemble"]["needs"] == ["prepare", "analyze"]
    assert jobs["sign"]["needs"] == "assemble"
    assert "id-token" not in jobs["assemble"]["permissions"]
    build, upload = jobs["prepare"]["steps"]
    pin = "REVIEW_CHALLENGE_SUMMARY_SHA256"
    assert (
        build["env"][pin] == "${{ vars.CODE_FACTORY_NATIVE_REVIEW_CHALLENGE_SHA256 }}"
    )
    assert jobs["prepare"]["outputs"]["challenge_summary_sha256"] == (
        "${{ steps.build.outputs.challenge_summary_sha256 }}"
    )
    assert (
        jobs["analyze"]["env"][pin]
        == jobs["assemble"]["env"][pin]
        == ("${{ needs.prepare.outputs.challenge_summary_sha256 }}")
    )
    assert "review_packet" not in build["run"] and "cmake --build" in build["run"]
    assert "keyless-review-runtime-%s" in build["run"]
    assert upload["with"]["path"] == "llama/build/bin/llama-server"
    download = next(
        item
        for item in jobs["analyze"]["steps"]
        if item.get("uses", "").startswith("actions/download-artifact@")
    )
    assert download["with"] == {
        "name": "${{ needs.prepare.outputs.artifact_name }}",
        "path": "reviewer-runtime",
    }
    verify_artifacts = next(
        item["run"]
        for item in jobs["analyze"]["steps"]
        if item.get("name") == "Verify the reviewer runtime and model"
    )
    assert (
        "--max-time 180" in verify_artifacts and "--continue-at -" in verify_artifacts
    )
    assert '"$attempt" -eq 4' in verify_artifacts
    assert verify_artifacts.count("sha256sum -c -") == 2
    paths = {path for row in plan["obligations"] for path in row["paths"]}
    for row in plan["obligations"]:
        for challenge in row["challenges"]:
            paths.add(challenge["fixture_path"])
            paths.update(challenge["fixture_manifest"])
    assert len(paths) == 19
    packet = {
        "binding": {"candidate_sha256": plan["candidate_sha256"]},
        "sources": {path: "synthetic test text" for path in paths},
        "observations": [
            {
                "lane_id": lane["id"],
                "engine": lane["engine"],
                "state": "OBSERVED",
                "gaps": [],
                "findings": [],
                "metrics": None,
                "report_sha256": "1" * 64,
                "coverage_sha256": "2" * 64,
                "challenge_sha256": sha256_bytes(lane["id"].encode()),
                "obligations": [
                    item["id"]
                    for item in plan["obligations"]
                    if item["engine"] == lane["engine"]
                ],
            }
            for lane in plan["lanes"]
        ],
    }
    return review, plan_path, plan, families, paths, packet


def _reject_invalid_family_input(review, plan, packet, mode):
    if mode == "unbound_obligation":
        packet["observations"][0]["obligations"] = []
        with pytest.raises(ValueError, match="differ from the observed lanes"):
            review.family_inputs(plan, packet)
        return True
    if mode in {"missing_receipt", "malformed_receipt"}:
        packet["observations"][0]["challenge_sha256"] = (
            None if mode == "missing_receipt" else "x" * 64
        )
        with pytest.raises(RuntimeAuditError, match="challenge_sha256"):
            review.family_inputs(plan, packet)
        return True
    if mode in {"incomplete_observation", "lane_gap"}:
        if mode == "incomplete_observation":
            packet["observations"][0]["state"] = "INCOMPLETE"
        else:
            packet["observations"][0]["gaps"] = ["missing report"]
        with pytest.raises(ValueError, match="incomplete analyzer lane"):
            review.family_inputs(plan, packet)
        return True
    return False


def _configure_challenge_receipts(review, plan, packet, mode):
    expected_errors = {
        "wrong_challenge_digest": "differs from the registered receipt",
        "wrong_challenge_run": "different analyzer evidence",
        "wrong_challenge_lane": "lane digest differs",
        "missing_challenge": "outcomes differ from registered controls",
        "duplicate_challenge": "duplicate recorded challenge",
    }
    if mode == "challenge_receipts" or mode in expected_errors:
        packet["binding"].update(run_id="archived-synthetic", evidence_sha256="6" * 64)
        receipts = {
            "schema": "factory.keyless-challenge-summary.v1",
            "run_id": "archived-synthetic",
            "evidence_sha256": "6" * 64,
            "lanes": {
                lane["lane_id"]: {
                    "challenge_sha256": lane["challenge_sha256"],
                    "observations": [
                        {
                            "obligation_id": row["id"],
                            "role": item["kind"],
                            "exit_code": item["expected_exit_code"],
                            "fixture_sha256": item["fixture_sha256"],
                            "report_sha256": item["expected_report_sha256"],
                            "observation_sha256": "8" * 64,
                            "detector_configuration_changed": item["kind"]
                            == "mutation",
                        }
                        for row in plan["obligations"]
                        for item in row["challenges"]
                        if row["engine"] == lane["engine"]
                    ],
                }
                for lane in packet["observations"]
            },
        }
        packet["challenge_receipts"] = receipts
        initial_receipt_sha256 = digest(receipts)
        first_rows = receipts["lanes"]["codeql"]["observations"]
        if mode == "wrong_challenge_digest":
            first_rows[0]["exit_code"] += 1
        elif mode == "wrong_challenge_run":
            receipts["run_id"] = "unrelated-run"
        elif mode == "wrong_challenge_lane":
            receipts["lanes"]["codeql"]["challenge_sha256"] = receipts["lanes"]["osv"][
                "challenge_sha256"
            ]
        elif mode == "missing_challenge":
            first_rows.pop()
        elif mode == "duplicate_challenge":
            first_rows.append(first_rows[0])
        review.CHALLENGE_SUMMARY_SHA256 = (
            initial_receipt_sha256
            if mode == "wrong_challenge_digest"
            else digest(receipts)
        )
        if mode in expected_errors:
            with pytest.raises(ValueError, match=expected_errors[mode]):
                review.family_inputs(plan, packet)
            return True
    return False


def test_keyless_review_requires_the_independently_registered_control_summary(
    monkeypatch,
):
    review, _plan_path, plan, _families, _paths, packet = _keyless_review_fixture()
    historical = review.CHALLENGE_SUMMARY_SHA256
    _configure_challenge_receipts(review, plan, packet, "challenge_receipts")
    summary = packet["challenge_receipts"]
    current = digest(summary)
    assert current != historical
    review.CHALLENGE_SUMMARY_SHA256 = historical
    monkeypatch.setenv("REVIEW_CHALLENGE_SUMMARY_SHA256", current)

    families = review.family_inputs(plan, packet)
    assert sum(len(row["sources"]) for row in families) == 58
    assert (
        sum(
            "observed_challenge" in control
            for row in families
            for obligation in row["obligations"]
            for control in obligation["controls"]
        )
        == 30
    )

    packet["binding"]["run_id"] = "wrong-run"
    with pytest.raises(ValueError, match="different analyzer evidence"):
        review.family_inputs(plan, packet)
    packet["binding"]["run_id"] = summary["run_id"]
    monkeypatch.setenv("REVIEW_CHALLENGE_SUMMARY_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="registered receipt"):
        review.family_inputs(plan, packet)
    monkeypatch.setenv("REVIEW_CHALLENGE_SUMMARY_SHA256", current)
    del packet["challenge_receipts"]
    with pytest.raises(ValueError, match="registered challenge summary is missing"):
        review.family_inputs(plan, packet)


def _stage_family_review(tmp_path, monkeypatch, plan_path, packet):
    monkeypatch.chdir(tmp_path)
    staged_plan = tmp_path / "scripts" / plan_path.name
    staged_plan.parent.mkdir()
    staged_plan.write_bytes(plan_path.read_bytes())
    (tmp_path / "review-model-input.json").write_text(
        json.dumps(packet), encoding="utf-8"
    )
    monkeypatch.setenv("GITHUB_RUN_ID", "fixture-only")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("REVIEW_RUNTIME_SHA256", "4" * 64)
    summary_path = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    return summary_path


def _rationale_reply(body, payload, assigned, mode):
    selected = payload["rationale_paths"]
    assert payload["family"] == "dependencies" and selected == assigned[:2]
    assert sorted(body["response_format"]["schema"]["required"]) == selected
    assert body["max_tokens"] < 2600
    recovered = {
        path: {
            "state": "REVIEWED",
            "reason": "REVIEWED"
            if mode == "status_only_rationale"
            else "Checked the bound dependency control outcome",
        }
        for path in selected
    }
    return BytesIO(
        json.dumps(
            {
                "choices": [
                    {
                        "message": {"content": json.dumps(recovered)},
                        "finish_reason": "stop",
                    }
                ]
            }
        ).encode()
    )


def _assert_unbound_family_prompt(payload, body, review, lane_ids, mode):
    assert {
        control["role"] for row in payload["obligations"] for control in row["controls"]
    } == {
        "positive",
        "negative",
        "mutation",
    }
    for row in payload["obligations"]:
        controls = {item["role"]: item["fixture_path"] for item in row["controls"]}
        assert controls["positive"] == controls["mutation"] != controls["negative"]
    assert all(
        lane["receipts"]
        == {
            "report_sha256": "1" * 64,
            "coverage_sha256": "2" * 64,
            "challenge_sha256": sha256_bytes(lane_ids[lane["engine"]].encode()),
        }
        for lane in payload["observations"]
    )
    if payload["family"] == "dependencies":
        inventory = next(
            lane for lane in payload["observations"] if lane["engine"] == "syft"
        )
        assert inventory["artifact_roles"] == ["sbom_json"]
        assert inventory["findings"] == []
    assert mode != "challenge_receipts"
    assert all(
        {"observed_challenge", "expected_exit_code"}.isdisjoint(control)
        for obligation in payload["obligations"]
        for control in obligation["controls"]
    )
    assert body["messages"][0]["content"] == review.INSTRUCTIONS


def _family_reply(payload, assigned, mode):
    result = {
        "decision": "ACCEPT",
        "findings": [],
        "coverage_gaps": [],
        "path_assessments": {
            path: {"state": "REVIEWED", "reason": "Synthetic evidence reviewed"}
            for path in assigned
        },
    }
    if mode == "unresolved" and payload["family"] == "dependencies":
        result["path_assessments"][assigned[0]] = {
            "state": "UNRESOLVED",
            "reason": "Manifest has insufficient evidence",
        }
        result["findings"] = [
            {
                "id": "fixture-finding",
                "severity": "low",
                "path": assigned[-1],
                "evidence": "Synthetic evidence disposition",
                "remediation": "Review the fixture evidence",
            }
        ]
    if (
        mode in {"no_indicator", "conflicting_assessment"}
        and payload["family"] == "secrets"
    ):
        result["path_assessments"][assigned[0]] = {
            "state": "REVIEWED_NO_INDICATOR",
            "reason": "Inspected the assigned text for secret indicators",
        }
        if mode == "conflicting_assessment":
            result["findings"] = [
                {
                    "id": "conflicting-finding",
                    "severity": "low",
                    "path": assigned[0],
                    "evidence": "Synthetic indicator claim",
                    "remediation": "Inspect the recorded indicator",
                }
            ]
    if (
        mode
        in {
            "status_only_rationale",
            "rationale_recovered",
            "rationale_retry_tamper",
        }
        and payload["family"] == "dependencies"
    ):
        result["path_assessments"][assigned[0]]["reason"] = "REVIEWED"
        result["path_assessments"][assigned[1]] = {
            "state": "REVIEWED_NO_INDICATOR",
            "reason": "  reviewed_no_indicator  ",
        }
        if mode == "rationale_recovered":
            result["findings"] = [
                {
                    "id": "retained-first-pass-finding",
                    "path": assigned[2],
                    "severity": "low",
                    "evidence": "Synthetic finding recorded in the first response",
                    "remediation": "Review this synthetic observation",
                }
            ]
    if mode == "obligation_gap" and payload["family"] == "dependencies":
        result["coverage_gaps"] = [
            "The ledger lacks evidence for a declared dependency obligation"
        ]
    if mode == "omitted":
        del result["path_assessments"][assigned[0]]
    if mode == "out_of_scope":
        result["path_assessments"]["outside.txt"] = result["path_assessments"][
            assigned[0]
        ]
    finish = "length" if mode == "truncated" else "stop"
    return BytesIO(
        json.dumps(
            {
                "choices": [
                    {
                        "message": {"content": json.dumps(result)},
                        "finish_reason": finish,
                    }
                ]
            }
        ).encode()
    )


def _grounded_rationale_reply(body, payload, sources):
    selected = sorted(path for path in sources if path.endswith("requirements.txt"))[:2]
    schema = body["response_format"]["schema"]
    assert sorted(payload["sources"]) == selected == schema["required"]
    assert set(payload["path_evidence"]) == set(selected)
    assert body["max_tokens"] == 128 * len(selected)
    recovered = {
        path: {
            "state": "REVIEWED",
            "source_fact": "The synthetic test text states the scope of the fixture.",
            "source_excerpt": "synthetic test text",
            "source_line": 1,
        }
        for path in selected
    }
    choice = {"message": {"content": json.dumps(recovered)}, "finish_reason": "stop"}
    return BytesIO(json.dumps({"choices": [choice]}).encode())


class _KeylessReviewResponder:
    def __init__(self, review, plan, packet, mode):
        self.review = review
        self.plan = plan
        self.packet = packet
        self.mode = mode
        self.lane_ids = {row["engine"]: row["id"] for row in plan["lanes"]}
        self.expected_coverage = set()

    def __call__(self, request, timeout):
        review = self.review
        if isinstance(request, str):
            assert request == review.LOOPBACK + "/health"
            health = BytesIO()
            health.status = 200
            return health
        assert request.full_url == review.LOOPBACK + "/v1/chat/completions"
        assert 0 < timeout <= 1200
        body = json.loads(request.data)
        payload = json.loads(body["messages"][1]["content"])
        assigned = sorted(payload["sources"])
        if payload.get("rationale_paths"):
            return _rationale_reply(body, payload, assigned, self.mode)
        if "earlier citations" in body["messages"][0]["content"]:
            assert (
                self.mode == "challenge_receipts"
                and payload["family"] == "dependencies"
            )
            return _grounded_rationale_reply(body, payload, self.packet["sources"])
        schema = body["response_format"]["schema"]["properties"]["path_assessments"]
        assert (
            schema["required"] == assigned and schema["additionalProperties"] is False
        )
        if "path_evidence" in payload:
            return self.challenge_reply(body, payload, assigned, schema)
        _assert_unbound_family_prompt(payload, body, review, self.lane_ids, self.mode)
        self.expected_coverage.update(assigned)
        return _family_reply(payload, assigned, self.mode)

    def challenge_reply(self, body, payload, assigned, schema):
        review, plan, packet = self.review, self.plan, self.packet
        mode, lane_ids = self.mode, self.lane_ids
        receipts = packet["challenge_receipts"]
        assert mode == "challenge_receipts"
        assert set(payload["path_evidence"]) == set(assigned)
        family_obligations = [
            row for row in plan["obligations"] if row["family"] == payload["family"]
        ]
        family_obligation = family_obligations[0]
        observed = receipts["lanes"][lane_ids[family_obligation["engine"]]][
            "observations"
        ]
        for path in assigned:
            source = packet["sources"][path]
            assert payload["sources"][path] == list(
                map(list, enumerate(source.splitlines(), 1))
            )
            path_evidence = payload["path_evidence"][path]
            assert path_evidence["source_sha256"] == sha256_bytes(source.encode())
            assert path_evidence.get("requirements", []) == [
                row["id"] for row in family_obligations if path in row["requirements"]
            ]
            controls = {
                (row["id"], control["kind"]): (row, control)
                for row in family_obligations
                for control in row["challenges"]
                if control["fixture_path"] == path
            }
            supplied = {
                (control["obligation"], control["role"]): control
                for control in path_evidence.get("entrypoint_controls", [])
            }
            assert set(supplied) == set(controls)
            for (identity, role), control in supplied.items():
                obligation, registered = controls[(identity, role)]
                lane_receipts = receipts["lanes"][lane_ids[obligation["engine"]]][
                    "observations"
                ]
                receipt = next(
                    row
                    for row in lane_receipts
                    if row["role"] == role and row["obligation_id"] == identity
                )
                assert (
                    control["exit_code"]
                    == registered["expected_exit_code"]
                    == receipt["exit_code"]
                )
                assert control["observation_sha256"] == receipt["observation_sha256"]
            assert path_evidence.get("supporting_controls", []) == [
                [row["id"], control["kind"]]
                for row in family_obligations
                for control in row["challenges"]
                if path in control["fixture_manifest"]
                and path != control["fixture_path"]
            ]
        assert "They do not establish execution" in body["messages"][0]["content"]
        assert "obligations" not in payload and "observations" not in payload
        family_input = next(
            item
            for item in review.family_inputs(plan, packet)
            if item["family"] == payload["family"]
        )
        retry = json.loads(
            review.rationale_messages(family_input, assigned[:1])[1]["content"]
        )
        assert retry["sources"] == {assigned[0]: payload["sources"][assigned[0]]}
        assert retry["path_evidence"] == {
            assigned[0]: payload["path_evidence"][assigned[0]]
        }
        self.expected_coverage.update(assigned)
        assert {"decision", "coverage_gaps"}.isdisjoint(
            body["response_format"]["schema"]["properties"]
        )
        positive = next(
            item
            for item in family_obligation["challenges"]
            if item["kind"] == "positive"
        )
        positive_path = positive["fixture_path"]
        positive_receipt = next(
            item
            for item in observed
            if item["role"] == "positive"
            and item["obligation_id"] == family_obligation["id"]
        )
        claim = {
            "kind": "exit_mismatch",
            "obligation": family_obligation["id"],
            "path": positive_path,
            "role": "positive",
            "observation_sha256": positive_receipt["observation_sha256"],
            "reason": "The positive exit was incorrectly reported as a defect.",
        }
        source = packet["sources"][positive_path].splitlines()[0]
        finding = {
            "id": "REVIEWED",
            "severity": "low",
            "path": positive_path,
            "evidence": "A routine source observation.",
            "remediation": "Inspect the source.",
            "source_line": 1,
            "source_excerpt": source,
        }
        result = {
            "findings": [finding],
            "control_claims": [
                claim,
                {**claim, "kind": "missing_observation", "observation_sha256": ""},
            ],
            "path_assessments": {
                path: {
                    "state": "REVIEWED",
                    "source_fact": "Inspected the synthetic test text for the control.",
                    "source_line": 1,
                    "source_excerpt": "synthetic test text",
                }
                for path in assigned
            },
        }
        grounded, rejected = review.ground_observed_response(result, family_input)
        assert len(rejected) == 3 and grounded["decision"] == "ACCEPT"
        assert not grounded["coverage_gaps"] and not grounded["findings"]
        genuine = {**finding, "id": "fixture-source-defect"}
        grounded, _ = review.ground_observed_response(
            {**result, "findings": [genuine]}, family_input
        )
        assert grounded["findings"][0]["id"] == genuine["id"]
        native = {
            **family_input,
            "observations": [
                {
                    "engine": "fixture",
                    "findings": [
                        {
                            "path": positive_path,
                            "line": 1,
                            "rule_id": "native-rule",
                            "suppressed": False,
                        }
                    ],
                }
            ],
        }
        for identity in (
            "native-rule",
            "fixture:native-rule",
            "fixture-native-rule",
        ):
            grounded, rejected = review.ground_observed_response(
                {**result, "findings": [{**genuine, "id": identity}, genuine]},
                native,
            )
            assert [row["id"] for row in grounded["findings"]] == [genuine["id"]]
            assert rejected[0]["kind"] == "existing_native_finding"
            assert rejected[0]["native"]["line"] == 1
        different_line = {**genuine, "id": "native-rule", "source_line": 2}
        native["sources"] = {
            **native["sources"],
            positive_path: f"{source}\n{source}",
        }
        grounded, _ = review.ground_observed_response(
            {**result, "findings": [different_line]}, native
        )
        assert [row["id"] for row in grounded["findings"]] == ["native-rule"]
        unresolved = {
            **result,
            "path_assessments": {
                **result["path_assessments"],
                positive_path: {
                    **result["path_assessments"][positive_path],
                    "state": "UNRESOLVED",
                    "source_fact": "Specific source evidence missing",
                },
            },
        }
        raw = json.dumps(
            {
                "choices": [
                    {
                        "message": {"content": json.dumps(unresolved)},
                        "finish_reason": "stop",
                    }
                ]
            }
        )
        recorded = review.recorded_response(raw.encode(), family_input)
        disposition = review.disposition(
            [
                {
                    "family": payload["family"],
                    "result": recorded,
                    "assigned_paths": assigned,
                }
            ]
        )
        assert disposition["decision"] == "INCOMPLETE"
        assert disposition["coverage_gaps"] == [
            f"{payload['family']}: unresolved review for {positive_path}: Specific source evidence missing"
        ]
        with pytest.raises(ValueError, match="invalid grounded review response"):
            review.ground_observed_response(
                {**result, "coverage_gaps": []}, family_input
            )
        for echo in ("", "\t\n", "a" * 161, f"{source}\nseparate line"):
            grounded, _ = review.ground_observed_response(
                {**result, "findings": [{**genuine, "source_excerpt": echo}]},
                family_input,
            )
            assert grounded["decision"] == "INCOMPLETE" and not grounded["findings"]
            assert grounded["coverage_gaps"] == [
                f"{positive_path}: source finding lacks its exact quoted line"
            ]
        quoted = {
            **family_input,
            "sources": {
                **family_input["sources"],
                positive_path: "source\tvalue\n",
            },
        }
        grounded, _ = review.ground_observed_response(
            {
                **result,
                "findings": [{**genuine, "source_excerpt": "source\tvalue\n"}],
            },
            quoted,
        )
        assert grounded["findings"][0]["id"] == genuine["id"]
        unbound = {**claim, "observation_sha256": "f" * 64}
        grounded, rejected = review.ground_observed_response(
            {
                **result,
                "control_claims": [unbound],
                "findings": [{**genuine, "source_line": 999_999}],
            },
            family_input,
        )
        assert (
            grounded["decision"] == "INCOMPLETE" and len(grounded["coverage_gaps"]) == 1
        )
        assert rejected[0]["kind"] == "contradicted_control_claim"
        assert rejected[0]["reference_matches"] is False
        assert not grounded["findings"]
        assert schema["properties"][positive_path]["properties"]["source_fact"][
            "minLength"
        ] > len("REVIEWED_NO_INDICATOR")
        proven = result["path_assessments"]
        assert (
            review.reviewed_paths(
                review.grounded_assessments(proven, family_input["sources"])
            )
            == assigned
        )
        paraphrased = {
            path: {
                **row,
                "source_fact": "The synthetic input describes the scope of the fixture.",
            }
            for path, row in proven.items()
        }
        assert (
            review.reviewed_paths(
                review.grounded_assessments(paraphrased, family_input["sources"])
            )
            == assigned
        )
        cited = {"source_line": 1, "source_excerpt": "def test_owned_control():"}
        assert review.source_supports_fact(
            cited,
            "def test_owned_control():\n    pass",
            "This function tests the owned control outcome.",
        )
        for unsupported in (
            {"source_fact": "REVIEWED"},
            {"source_fact": "This file only lists pinned package versions."},
            {"source_line": 2},
            {
                "source_excerpt": "pinned package versions",
                "source_fact": "This file only lists pinned package versions.",
            },
        ):
            followup = {path: {**row, **unsupported} for path, row in proven.items()}
            assert not review.reviewed_paths(
                review.grounded_assessments(followup, family_input["sources"])
            )
        observed_control = next(
            item
            for obligation in family_input["obligations"]
            if obligation["id"] == claim["obligation"]
            for item in obligation["controls"]
            if item["role"] == "positive"
        )
        observation = observed_control.pop("observed_challenge")
        try:
            grounded, _ = review.ground_observed_response(
                {**result, "control_claims": [claim]}, family_input
            )
            assert grounded["decision"] == "INCOMPLETE"
            assert "unverified control claim" in grounded["coverage_gaps"][0]
        finally:
            observed_control["observed_challenge"] = observation
        invalid = {**result, "findings": [{**genuine, "remediation": ""}]}
        malformed = json.dumps(
            {
                "choices": [
                    {
                        "message": {"content": json.dumps(invalid)},
                        "finish_reason": "stop",
                    }
                ]
            }
        )
        recorded = review.recorded_response(malformed.encode(), family_input)
        assert recorded["decision"] == "INCOMPLETE" and not recorded["findings"]
        assert set(recorded["path_assessments"]) == set(assigned)
        assert all(
            row["state"] == "UNRESOLVED"
            for row in recorded["path_assessments"].values()
        )
        disposition = review.disposition(
            [
                {
                    "family": payload["family"],
                    "result": recorded,
                    "assigned_paths": assigned,
                }
            ]
        )
        assert disposition["decision"] == "INCOMPLETE"
        assert len(disposition["coverage_gaps"]) == len(assigned)
        if payload["family"] == "dependencies":
            result["path_assessments"][assigned[0]]["source_line"] = 2
            result["path_assessments"][assigned[1]]["source_fact"] = (
                "This file only lists pinned package versions."
            )
        return BytesIO(
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {"content": json.dumps(result)},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode()
        )


def _write_family_outputs(review, tmp_path, monkeypatch, mode, families, outputs):
    for family in sorted(families, reverse=True):
        if mode == "missing" and family == "dependencies":
            continue
        monkeypatch.setenv("REVIEW_FAMILY", family)
        review.main()
        output = outputs / f"keyless-review-family-1-{family}"
        output.mkdir()
        (tmp_path / "review-family.json").replace(output / "review-family.json")
    monkeypatch.delenv("REVIEW_FAMILY")


def _reject_invalid_assembly(review, tmp_path, monkeypatch, mode, outputs):
    if mode == "rationale_retry_tamper":
        path = outputs / "keyless-review-family-1-dependencies/review-family.json"
        part = json.loads(path.read_bytes())
        part["rationale_recovery"]["raw_response"] += " "
        path.write_text(json.dumps(part), encoding="utf-8")
        with pytest.raises(ValueError, match="rationale recovery response fingerprint"):
            review.main()
        assert not (tmp_path / "review.json").exists()
        return True
    if mode in {"missing", "wrong_attempt", "wrong_runtime", "modified_response"}:
        if mode == "wrong_attempt":
            monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
        if mode in {"wrong_runtime", "modified_response"}:
            path = outputs / "keyless-review-family-1-dependencies/review-family.json"
            part = json.loads(path.read_bytes())
            if mode == "wrong_runtime":
                part["identity"]["runtime_sha256"] = "5" * 64
            else:
                part["raw_response"] += " "
            path.write_text(json.dumps(part), encoding="utf-8")
        with pytest.raises(ValueError):
            review.main()
        assert not (tmp_path / "review.json").exists()
        return True
    return False


def _assert_family_output(tmp_path, summary_path, expected_coverage, paths):
    result = json.loads((tmp_path / "review.json").read_bytes())
    coverage = json.loads((tmp_path / "review-coverage.json").read_bytes())
    assert expected_coverage == paths
    assert len({row["family"] for row in coverage}) == 6
    assert {row["runtime_sha256"] for row in coverage} == {"4" * 64}
    for row in coverage:
        assert row["response_sha256"] == sha256_bytes(row["raw_response"].encode())
        if recovery := row.get("rationale_recovery"):
            assert recovery["response_sha256"] == sha256_bytes(
                recovery["raw_response"].encode()
            )
    for field in ("prompt_sha256", "response_sha256"):
        assert result[field] == digest(
            [
                digest([row[field], row["rationale_recovery"][field]])
                if row.get("rationale_recovery")
                else row[field]
                for row in coverage
            ]
        )
    assert result["authority"] == "none"
    summary = summary_path.read_text(encoding="utf-8")
    assert f"Six-family review · {result['decision']}" in summary
    assert "Analyzer alerts | Review findings" in summary
    return result, coverage, summary


def _assert_family_decision(mode, result, coverage, summary):
    if mode == "unresolved":
        assert result["decision"] == "INCOMPLETE"
        assert len(result["coverage_gaps"]) == 1
        assert result["coverage_gaps"][0].startswith(
            "dependencies: unresolved review for "
        )
        assert result["coverage_gaps"][0].endswith("Manifest has insufficient evidence")
        assert [finding["id"] for finding in result["findings"]] == ["fixture-finding"]
        assert "| dependencies | 3 | 2 | 1 | 0 | 1 |" in summary
    elif mode == "rationale_recovered":
        assert result["decision"] == "FINDINGS" and result["coverage_gaps"] == []
        assert [f["id"] for f in result["findings"]] == ["retained-first-pass-finding"]
        row = next(x for x in coverage if x["family"] == "dependencies")
        assert row["assigned_paths"] == row["result"]["reviewed_paths"]
        assert len(row["rationale_recovery"]["paths"]) == 2
    elif mode == "status_only_rationale":
        assert result["decision"] == "INCOMPLETE"
        assert len(result["coverage_gaps"]) == 2
        assert all(
            gap.endswith("missing rationale beyond the assessment status")
            for gap in result["coverage_gaps"]
        )
        dependencies = next(row for row in coverage if row["family"] == "dependencies")
        assert len(dependencies["result"]["reviewed_paths"]) == 1
        assert "REVIEWED" in dependencies["raw_response"]
    elif mode == "conflicting_assessment":
        assert result["decision"] == "INCOMPLETE"
        assert len(result["coverage_gaps"]) == 1
        assert result["coverage_gaps"][0].startswith(
            "secrets: finding conflicts with no-indicator assessment for "
        )
        assert [finding["id"] for finding in result["findings"]] == [
            "conflicting-finding"
        ]
    elif mode == "no_indicator":
        assert result["decision"] == "ACCEPT" and result["coverage_gaps"] == []
        secrets = next(row for row in coverage if row["family"] == "secrets")
        assert secrets["result"]["reviewed_paths"] == secrets["assigned_paths"]
    elif mode == "challenge_receipts":
        assert result["decision"] == "ACCEPT" and not result["findings"]
        assert not result["coverage_gaps"]
        recovered = [row for row in coverage if "rationale_recovery" in row]
        assert [row["family"] for row in recovered] == ["dependencies"]
        assert (
            recovered[0]["result"]["reviewed_paths"] == recovered[0]["assigned_paths"]
        )
        for row in coverage:
            if row["family"] in {"runtime", "fuzz"}:
                assert [
                    claim["kind"] for claim in row["result"]["rejected_claims"]
                ] == [
                    "assessment_status_as_finding",
                    "contradicted_control_claim",
                    "contradicted_control_claim",
                ]
                assert len(row["result"]["reviewed_paths"]) == len(
                    row["assigned_paths"]
                )
                assert "incorrectly reported as a defect" in row["raw_response"]
    elif mode == "obligation_gap":
        assert result["decision"] == "INCOMPLETE"
        assert result["coverage_gaps"] == [
            "The ledger lacks evidence for a declared dependency obligation"
        ]
    else:
        assert result["decision"] == "ACCEPT" and result["coverage_gaps"] == []


@pytest.mark.parametrize(
    "mode",
    [
        "complete",
        "unresolved",
        "obligation_gap",
        "no_indicator",
        "conflicting_assessment",
        "status_only_rationale",
        "rationale_recovered",
        "rationale_retry_tamper",
        "omitted",
        "out_of_scope",
        "truncated",
        "missing",
        "wrong_attempt",
        "wrong_runtime",
        "modified_response",
        "unbound_obligation",
        "missing_receipt",
        "malformed_receipt",
        "incomplete_observation",
        "lane_gap",
        "challenge_receipts",
        "wrong_challenge_digest",
        "wrong_challenge_run",
        "wrong_challenge_lane",
        "missing_challenge",
        "duplicate_challenge",
    ],
)
def test_keyless_review_requires_exact_family_coverage(tmp_path, monkeypatch, mode):
    review, plan_path, plan, families, paths, packet = _keyless_review_fixture()
    if _reject_invalid_family_input(review, plan, packet, mode):
        return
    if _configure_challenge_receipts(review, plan, packet, mode):
        return
    summary_path = _stage_family_review(tmp_path, monkeypatch, plan_path, packet)
    responder = _KeylessReviewResponder(review, plan, packet, mode)
    monkeypatch.setattr(review, "urlopen", responder)
    outputs = tmp_path / "family-outputs"
    outputs.mkdir()
    family = sorted(families)[0]
    monkeypatch.setenv("REVIEW_FAMILY", family)
    if mode in {"omitted", "out_of_scope", "truncated"}:
        with pytest.raises(ValueError):
            review.main()
        assert not (tmp_path / "review.json").exists()
        return
    _write_family_outputs(review, tmp_path, monkeypatch, mode, families, outputs)
    if _reject_invalid_assembly(review, tmp_path, monkeypatch, mode, outputs):
        return
    review.main()
    result, coverage, summary = _assert_family_output(
        tmp_path, summary_path, responder.expected_coverage, paths
    )
    _assert_family_decision(mode, result, coverage, summary)


def _keyless_authorization_fixture(tmp_path):
    from factoryline.deep_audit_io import digest, sha256_bytes

    identities = {
        role: f"https://github.com/example/repo/.github/workflows/{role}.yml@refs/heads/main"
        for role in ("implementer", "reviewer", "coordinator")
    }
    roles = {
        role: {"identity": identity, "keyid": role, "workflow_digest": "a" * 40}
        for role, identity in identities.items()
    }
    trust = tmp_path / "trust.json"
    trust.write_text(
        json.dumps({"schema": "factory.deep-audit-sigstore-trust.v1", "roles": roles}),
        encoding="utf-8",
    )
    plan = {
        "implementer_id": identities["implementer"],
        "reviewer_identity": identities["reviewer"],
        "coordinator_identity": identities["coordinator"],
        **{f"{role}_keyid": role for role in roles},
        "trust_root_sha256": sha256_bytes(trust.read_bytes()),
        "candidate_sha256": "b" * 64,
        "lanes": [{"id": "osv", "image": "sha256:" + "c" * 64}],
    }
    pin = "d" * 64
    now = datetime.now(timezone.utc)
    payload = {
        "schema": "factory.deep-execution-authorization.v1",
        "manifest_sha256": pin,
        "manifest_content_sha256": digest(plan),
        "candidate_sha256": plan["candidate_sha256"],
        "adapter_images": {"osv": plan["lanes"][0]["image"]},
        "authority": "none",
        "issued_at": (now - timedelta(seconds=10)).isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
    }
    return roles, trust, plan, pin, payload


def test_keyless_authorization_verifies_pinned_bytes_and_native_bindings(
    tmp_path, monkeypatch
):
    from factoryline import deep_audit_attestation as module
    from factoryline.deep_audit_io import canonical_bytes, digest

    roles, trust, plan, pin, payload = _keyless_authorization_fixture(tmp_path)
    envelope = {"schema": module._KEYLESS_ENVELOPE, "payload": payload, "bundle": {}}
    authorization = tmp_path / "authorization.json"
    authorization.write_bytes(canonical_bytes(envelope))
    observed = []
    monkeypatch.setattr(
        module, "_verify_keyless_artifact", lambda *args: observed.append(args)
    )
    assert module.verify_execution_authorization(
        plan,
        pin,
        authorization,
        trust,
        plan["trust_root_sha256"],
        return_envelope_sha256=True,
    ) == (payload, digest(envelope))
    assert observed == [(canonical_bytes(payload), {}, roles["coordinator"])]
    payload["adapter_images"] = {}
    authorization.write_bytes(canonical_bytes(envelope))
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_AUTHORIZATION"):
        module.verify_execution_authorization(
            plan, pin, authorization, trust, plan["trust_root_sha256"]
        )


@pytest.mark.parametrize(
    "change",
    ["shared", "same_workflow_other_ref", "different_manifest_role", "bad_commit"],
)
def test_keyless_roles_reject_shared_or_drifted_identity(tmp_path, change):
    from factoryline import deep_audit_attestation as module

    roles, trust, plan, _, _ = _keyless_authorization_fixture(tmp_path)
    if change == "shared":
        roles["reviewer"]["identity"] = roles["coordinator"]["identity"]
    elif change == "same_workflow_other_ref":
        roles["reviewer"]["identity"] = roles["coordinator"]["identity"].replace(
            "refs/heads/main", "refs/tags/v1"
        )
    elif change == "different_manifest_role":
        plan["reviewer_keyid"] = "coordinator"
    else:
        roles["reviewer"]["workflow_digest"] = "refs/heads/main"
    trust.write_text(
        json.dumps({"schema": module._KEYLESS_TRUST, "roles": roles}), encoding="utf-8"
    )
    with pytest.raises(RuntimeAuditError, match="E_REVIEW_TRUST|E_REVIEW_IDENTITY"):
        module._execution_keys(plan, trust)


def _coordinator_test_request(root, operation="status"):
    return dict(
        version=1,
        operation=operation,
        workspace=str(root.resolve()),
        session_nonce="a" * 32,
        request_id="b" * 32,
    )


def _coordinator_cli_argv(root, *extra):
    import sys
    import factoryline.cli_deep_audit as module

    package = str(Path(module.__file__).resolve().parent.parent)
    bootstrap = (
        "import sys;sys.path.insert(0,"
        + repr(package)
        + ");from factoryline.cli import main;sys.exit(main(sys.argv[1:]))"
    )
    return [
        sys.executable,
        "-I",
        "-c",
        bootstrap,
        "deep-audit",
        "coordinator",
        "--root",
        str(root),
        "--session-nonce",
        "a" * 32,
        *extra,
    ]


def test_coordinator_windows_venv_launch_retains_worker_pid(tmp_path):
    import os
    import subprocess
    import venv

    if os.name != "nt":
        pytest.skip("Windows venv redirector behavior")
    from factoryline import cli_deep_audit

    env_root = tmp_path / "worker-venv"
    venv.EnvBuilder(with_pip=False).create(env_root)
    package = str(Path(cli_deep_audit.__file__).resolve().parent.parent)
    bootstrap = """
import json, subprocess, sys
sys.path.insert(0, sys.argv[1])
from factoryline.cli_deep_audit import _coordinator_worker_launch
executable, env = _coordinator_worker_launch()
assert executable == sys._base_executable and executable != sys.executable
source = "import json, os, sys; print(json.dumps([os.getpid(), sys.prefix, sys.executable]))"
with subprocess.Popen([executable, "-I", "-c", source], env=env, stdout=subprocess.PIPE, text=True) as worker:
    raw, _ = worker.communicate(timeout=25)
    assert worker.returncode == 0
    pid, prefix, interpreter = json.loads(raw)
    assert pid == worker.pid and prefix == sys.prefix and interpreter == sys.executable
"""
    subprocess.run(
        [str(env_root / "Scripts" / "python.exe"), "-I", "-c", bootstrap, package],
        check=True,
        timeout=40,
    )


def test_coordinator_public_cli_status_stop_ndjson(tmp_path):
    import subprocess
    import sys

    requests = [
        _coordinator_test_request(tmp_path, operation)
        for operation in ("status", "stop")
    ]
    requests[1]["request_id"] = "c" * 32
    result = subprocess.run(
        _coordinator_cli_argv(tmp_path),
        input="".join(json.dumps(row) + "\n" for row in requests).encode(),
        capture_output=True,
        timeout=20,
    )
    if sys.platform not in {"win32", "linux"}:
        _coordinator_cli_assert_unsupported(result, tmp_path)
        return
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 2 and rows[-1]["state"] == "STOPPED"
    assert all(
        row["authority"] == "none" and row["release_approval"] is False for row in rows
    )
    assert all(row.get("execution_available", False) is False for row in rows)


@pytest.mark.parametrize("ttl", ["0", "3601", "-1", "invalid"])
def test_coordinator_public_cli_rejects_invalid_lease(tmp_path, ttl):
    import subprocess

    result = subprocess.run(
        _coordinator_cli_argv(tmp_path, "--lease-seconds", ttl),
        input=b"",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode != 0
    assert not (tmp_path / ".factory/deep-runs/requests").exists()


@pytest.mark.parametrize("fault", ["nonce", "operation", "duplicate_json", "workspace"])
def test_coordinator_public_cli_protocol_refusal(tmp_path, fault):
    import subprocess
    import sys

    request = _coordinator_test_request(tmp_path)
    changes = {
        "nonce": {"session_nonce": "c" * 32},
        "operation": {"operation": "unexpected"},
        "workspace": {"workspace": str(tmp_path.parent)},
    }
    request.update(changes.get(fault, {}))
    raw = json.dumps(request)
    if fault == "duplicate_json":
        raw = raw[:-1] + ',"operation":"status"}'
    result = subprocess.run(
        _coordinator_cli_argv(tmp_path),
        input=(raw + "\n").encode(),
        capture_output=True,
        timeout=20,
    )
    if sys.platform not in {"win32", "linux"}:
        _coordinator_cli_assert_unsupported(result, tmp_path)
        return
    assert result.returncode == 1
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 1 and rows[0]["state"] == "INCOMPLETE"
    assert rows[0]["authority"] == "none" and rows[0]["release_approval"] is False


def test_coordinator_public_cli_rejects_buffered_input_without_closing(
    monkeypatch, tmp_path, capsys
):
    import io
    from types import SimpleNamespace
    import factoryline.cli_deep_audit as module

    stream = io.BytesIO()
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(buffer=stream))
    result = module._run_coordinator(
        SimpleNamespace(root=tmp_path, lease_seconds=300, session_nonce="a" * 32)
    )
    assert result == 2 and not stream.closed
    assert json.loads(capsys.readouterr().out)["state"] == "INCOMPLETE"


def test_coordinator_public_cli_signed_child_owned_stop(tmp_path):
    import subprocess
    import time
    import sys

    if sys.platform not in {"win32", "linux"}:
        pytest.skip(
            "NOT_RUN: native signed child identity supported on Windows/Linux only; refusal tested separately"
        )

    root, request, owner, context, inventory = _coordinator_signed_fixture(tmp_path)
    context["store"].release(owner)
    child = subprocess.Popen(
        _coordinator_cli_argv(root, "--lease-seconds", "90"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    handshake = None
    try:
        child.stdin.write((json.dumps(request) + "\n").encode())
        child.stdin.flush()
        deadline = time.monotonic() + 45
        while child.poll() is None and time.monotonic() < deadline:
            for path in (root / ".factory/deep-runs/requests").glob("*/handshake.json"):
                try:
                    handshake = json.loads(path.read_bytes())
                except (OSError, ValueError):
                    continue
            if handshake:
                break
            time.sleep(0.02)
        assert handshake, "public CLI did not observe a fresh signed child handshake"
        assert handshake["worker_identity"]["pid"] != child.pid
        assert handshake["request_id"] == request["request_id"]
        stop = _coordinator_test_request(root, "stop")
        stop["request_id"] = "d" * 32
        output, error = child.communicate(
            (json.dumps(stop) + "\n").encode(), timeout=30
        )
        assert child.returncode == 0, error
        rows = [json.loads(line) for line in output.splitlines()]
        assert rows[0]["state"] == "ADMITTED"
        assert rows[-1]["state"] == "STOPPED" and rows[-1]["cleanup_confirmed"] is True
        assert all(row.get("execution_available", False) is False for row in rows)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)


def _coordinator_transport_path(tmp_path):
    import os
    import shutil
    import sys

    git = shutil.which("git")
    assert git is not None
    git_directory = Path(git).parent
    if sys.platform == "linux":
        # A shared executable directory can contain both Git and Docker.
        git_directory = tmp_path / "git-only"
        git_directory.mkdir()
        shutil.copy2(git, git_directory / "git")
    test_path = os.pathsep.join([str(git_directory), str(Path(sys.executable).parent)])
    assert shutil.which("git", path=test_path)
    assert shutil.which("docker", path=test_path) is None
    return test_path


def test_coordinator_public_cli_terminal_replay_and_restart(tmp_path):
    import subprocess
    import time
    import os
    import sys
    from factoryline.agentic_control import CoordinatorRequestStore
    from factoryline.deep_audit import deep_run_status

    if sys.platform not in {"win32", "linux"}:
        pytest.skip(
            "NOT_RUN: native signed child identity supported on Windows/Linux only; refusal tested separately"
        )
    root, request, owner, context, _ = _coordinator_signed_fixture(tmp_path)
    context["store"].release(owner)
    child = subprocess.Popen(
        _coordinator_cli_argv(root, "--lease-seconds", "120"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PATH": _coordinator_transport_path(tmp_path)},
    )
    try:
        child.stdin.write((json.dumps(request) + "\n").encode())
        child.stdin.flush()
        terminal = _coordinator_cli_wait_terminal(
            root, request, child, time.monotonic() + 100
        )
        assert terminal["run_id"] and terminal["cleanup_confirmed"] is True
        assert terminal["state"] == "INCOMPLETE"
        status = deep_run_status(root, terminal["run_id"])
        assert status["analysis_complete"] is False
        failures = [
            json.loads(path.read_bytes())
            for path in (root / ".factory/deep-runs" / terminal["run_id"]).glob(
                "event-*.json"
            )
        ]
        assert any(
            row["kind"] == "failure_recorded"
            and row["details"].get("code") == "E_DOCKER_UNAVAILABLE"
            for row in failures
        )
        changed = {
            **request,
            "payload": {**request["payload"], "manifest_sha256": "0" * 64},
        }
        stop = _coordinator_test_request(root, "stop")
        stop["request_id"] = "d" * 32
        output, error = child.communicate(
            "".join(
                json.dumps(row) + "\n" for row in (request, changed, stop)
            ).encode(),
            timeout=20,
        )
        assert child.returncode == 0, error
        rows = [json.loads(line) for line in output.splitlines()]
        assert len(rows) == 4 and rows[0]["state"] == "ADMITTED"
        assert (
            rows[1]["run_id"] == terminal["run_id"]
            and rows[1]["state"] == terminal["state"]
        )
        assert (
            rows[2]["state"] == "INCOMPLETE"
            and rows[2]["code"] == "E_COORDINATOR_REQUEST"
        )
        assert rows[3]["state"] == "STOPPED"
        restarted = subprocess.run(
            _coordinator_cli_argv(root),
            input=(json.dumps(request) + "\n").encode(),
            capture_output=True,
            timeout=20,
        )
        assert restarted.returncode == 1
        assert json.loads(restarted.stdout)["code"] == "E_COORDINATOR_OWNER"
        assert (
            CoordinatorRequestStore(root).read(
                request["session_nonce"], request["request_id"]
            )["run_id"]
            == terminal["run_id"]
        )
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)


def _coordinator_cli_wait_terminal(root, request, child, deadline):
    import time
    from factoryline.agentic_control import CoordinatorRequestStore

    while child.poll() is None and time.monotonic() < deadline:
        try:
            # Observe atomic snapshots without repeatedly competing for the
            # production coordinator's exclusive metadata lock during launch.
            metadata = json.loads(
                (
                    root / ".factory/deep-runs/requests/coordinator-metadata.json"
                ).read_bytes()
            )
            key = request["session_nonce"] + ":" + request["request_id"]
            row = json.loads(metadata["rows"][key][0])
            if row["state"] not in {"ADMITTED", "RUNNING"}:
                return CoordinatorRequestStore(root).read(
                    request["session_nonce"], request["request_id"]
                )
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.05)
    pytest.fail("CLI did not retain bounded terminal request history")


def _coordinator_cli_assert_unsupported(result, root):
    assert result.returncode == 2, result.stderr
    row = json.loads(result.stdout)
    assert row["state"] == "INCOMPLETE" and row["code"] == "E_COORDINATOR_INPUT"
    assert row["authority"] == "none" and row["release_approval"] is False
    assert row["execution_available"] is False
    assert not (root / ".factory/deep-runs/requests/coordinator-metadata.json").exists()


def test_coordinator_public_cli_unsupported_identity_refuses_before_metadata(tmp_path):
    import subprocess

    argv = _coordinator_cli_argv(tmp_path)
    # Force only the existing identity observation to be unavailable, not the
    # parser, coordinator dispatcher, process cleanup or emitted refusal.
    argv[3] = argv[3].replace(
        "sys.exit(main(sys.argv[1:]))",
        "import factoryline.assembly_process as assembly;assembly._process_creation_identity=lambda pid:None;sys.exit(main(sys.argv[1:]))",
    )
    result = subprocess.run(argv, input=b"", capture_output=True, timeout=20)
    _coordinator_cli_assert_unsupported(result, tmp_path)


def _coordinator_test_payload(root):
    for name in ("manifest.json", "authorization.json", "trust.json"):
        (root / name).write_text("{}", encoding="utf-8")
    return dict(
        manifest="manifest.json",
        manifest_sha256="c" * 64,
        authorization="authorization.json",
        trust_root="trust.json",
        trust_root_sha256="d" * 64,
    )


@pytest.mark.parametrize("empty_implementation", [False, True])
def test_coordinator_smoke_runs_bound_source_and_rejects_noop(
    tmp_path, empty_implementation
):
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "smoke/deep-audit-coordinator-foundation-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(manifest["checks"]) == 1
    check = manifest["checks"][0]
    assert check["kind"] == "python" and check["must_fail_on_stub"] is True
    assert 0 < check["timeout_s"] <= 30 and check["expect_exit"] == 0
    if empty_implementation:
        root = tmp_path
        source = root / "factoryline/cli_deep_audit.py"
        source.parent.mkdir()
        source.write_text(
            "def serve_deep_audit_coordinator(*args, **kwargs):\n    return None\n",
            encoding="utf-8",
        )
    result = subprocess.run(
        [sys.executable, "-c", check["run"]],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=check["timeout_s"],
    )
    if empty_implementation:
        assert result.returncode != 0 and "invalid TTL admitted" in result.stderr
        assert check["expect_stdout"] not in result.stdout
    else:
        assert result.returncode == 0, result.stderr
        assert check["expect_stdout"] in result.stdout


@pytest.mark.parametrize("unicode_text", [False, True])
def test_coordinator_line_exact_utf8_byte_boundary(unicode_text):
    from factoryline.cli_deep_audit import _coordinator_line

    content = "é" * 100 if unicode_text else "x" * 100
    raw = json.dumps({"value": content}, ensure_ascii=False).encode("utf-8")
    exact = raw + b" " * (65536 - len(raw))
    assert _coordinator_line(exact) == {"value": content}
    assert _coordinator_line(exact.decode("utf-8")) == {"value": content}
    with pytest.raises(ValueError):
        _coordinator_line(exact + b" ")


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b"\xff", b"", b"{"])
def test_coordinator_line_rejects_invalid_encoding_or_json(raw):
    from factoryline.cli_deep_audit import _coordinator_line

    with pytest.raises((ValueError, RuntimeAuditError)):
        _coordinator_line(raw)


@pytest.mark.parametrize(
    "change",
    [
        {"version": True},
        {"version": 2},
        {"operation": "launch"},
        {"request_id": "A" * 32},
        {"request_id": "b" * 31},
        {"session_nonce": "g" * 32},
        {"session_nonce": None},
        {"executable": "python"},
        {"run_id": "c" * 32},
        {"payload": {}},
        {"workspace": "."},
    ],
)
def test_coordinator_request_rejects_invalid_envelope(tmp_path, change):
    from factoryline.cli_deep_audit import _coordinator_request

    request = _coordinator_test_request(tmp_path)
    request.update(change)
    with pytest.raises(ValueError):
        _coordinator_request(tmp_path, request)


@pytest.mark.parametrize("value", [[], None, 1, "status"])
def test_coordinator_request_requires_object(tmp_path, value):
    from factoryline.cli_deep_audit import _coordinator_request

    with pytest.raises(ValueError):
        _coordinator_request(tmp_path, value)


@pytest.mark.parametrize("operation", ["audit", "status", "stop"])
def test_coordinator_payload_is_required_only_for_audit(tmp_path, operation):
    from factoryline.cli_deep_audit import _coordinator_request

    value = _coordinator_test_request(tmp_path, operation)
    if operation != "audit":
        value["payload"] = _coordinator_test_payload(tmp_path)
    with pytest.raises(ValueError):
        _coordinator_request(tmp_path, value)


def test_coordinator_rejects_noncanonical_workspace_alias(tmp_path):
    from factoryline.cli_deep_audit import _coordinator_request

    value = _coordinator_test_request(tmp_path)
    value["workspace"] += "/."
    with pytest.raises(ValueError):
        _coordinator_request(tmp_path, value)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "escape", "absolute", "digest"],
)
def test_coordinator_audit_requires_exact_relative_bindings(tmp_path, mutation):
    from factoryline.cli_deep_audit import _coordinator_request

    request = _coordinator_test_request(tmp_path, "audit")
    payload = _coordinator_test_payload(tmp_path)
    request["payload"] = payload
    assert _coordinator_request(tmp_path, request) is None
    if mutation == "missing":
        del payload["authorization"]
    elif mutation == "extra":
        payload["executable"] = "python"
    elif mutation == "escape":
        payload["manifest"] = "../manifest.json"
    elif mutation == "absolute":
        payload["manifest"] = str(tmp_path / "manifest.json")
    else:
        payload["manifest_sha256"] = "z" * 64
    with pytest.raises((ValueError, RuntimeAuditError)):
        _coordinator_request(tmp_path, request)


@pytest.mark.parametrize("bad_path", ["missing.json", "directory"])
def test_coordinator_payload_files_checked_at_new_request_preflight(tmp_path, bad_path):
    from factoryline.cli_deep_audit import _coordinator_payload, _coordinator_request

    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    if bad_path == "directory":
        (tmp_path / bad_path).mkdir()
    request["payload"]["authorization"] = bad_path
    assert _coordinator_request(tmp_path, request) is None
    with pytest.raises((ValueError, RuntimeAuditError)):
        _coordinator_payload(tmp_path, request["payload"])


@pytest.mark.parametrize("drift", ["deleted", "changed"])
def test_coordinator_duplicate_readback_precedes_filesystem_preflight(
    tmp_path, monkeypatch, drift
):
    import factoryline.cli_deep_audit as module
    from factoryline.deep_audit_io import digest

    monkeypatch.setattr(
        module,
        "_coordinator_preflight",
        lambda *args: pytest.fail("duplicate must not rerun new-request preflight"),
    )
    owner, context = _coordinator_test_owner(tmp_path, module, monkeypatch)
    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    seal = digest(request)
    context["store"].admit(request["session_nonce"], request["request_id"], seal, owner)
    if drift == "deleted":
        for name in ("manifest.json", "authorization.json", "trust.json"):
            (tmp_path / name).unlink()
    else:
        (tmp_path / "manifest.json").write_text("changed", encoding="utf-8")
    result = module.dispatch_deep_audit_request(tmp_path, request, owner, context)
    assert result["state"] == "ADMITTED"
    assert context.get("job") is None


def test_coordinator_duplicate_changed_request_rejected_before_preflight(
    tmp_path, monkeypatch
):
    import factoryline.cli_deep_audit as module
    from factoryline.agentic_control import AgenticControlError
    from factoryline.deep_audit_io import digest

    monkeypatch.setattr(
        module,
        "_coordinator_preflight",
        lambda *args: pytest.fail("changed duplicate must not reach preflight"),
    )
    owner, context = _coordinator_test_owner(tmp_path, module, monkeypatch)
    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    context["store"].admit(
        request["session_nonce"], request["request_id"], digest(request), owner
    )
    request["payload"]["manifest_sha256"] = "e" * 64
    with pytest.raises(AgenticControlError) as caught:
        module.dispatch_deep_audit_request(tmp_path, request, owner, context)
    assert caught.value.code == "E_COORDINATOR_REQUEST"


@pytest.mark.parametrize("acknowledged", [False, True])
def test_coordinator_cancellation_keeps_existing_cleanup_window(
    tmp_path, monkeypatch, acknowledged
):
    import threading
    import time
    import factoryline.cli_deep_audit as module
    import factoryline.deep_audit as audit

    calls = []
    monkeypatch.setattr(
        audit,
        "cancel_deep_run",
        lambda root, run_id: calls.append((root, run_id))
        or {"state": "CANCELLATION_REQUESTED"},
    )
    job = dict(cancel=threading.Event(), acknowledged=acknowledged, run_id="a" * 32)
    module._coordinator_begin_cancel(tmp_path, job, 10)
    deadline = job["cancel_deadline"]
    assert job["cancel"].is_set()
    assert bool(calls) is acknowledged
    assert module._coordinator_cancel_grace(job, time.monotonic()) is acknowledged
    module._coordinator_begin_cancel(tmp_path, job, 10)
    assert job["cancel_deadline"] == deadline and len(calls) <= 1
    assert module._coordinator_cancel_grace(job, deadline + 1) is False
    assert job.get("cancel_hard_kill", False) is acknowledged


def test_coordinator_ack_is_marked_before_worker_can_observe_it(tmp_path, monkeypatch):
    """Synthetic publication-order control, not native process acceptance."""
    from types import SimpleNamespace
    import factoryline.cli_deep_audit as module
    import factoryline.assembly_process as assembly

    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = {}
    owner = {"pid": 10, "creation": "owner"}
    worker = {"pid": 11, "creation": "child"}
    job = dict(
        observed=worker,
        request_sha256="c" * 64,
        snapshot={},
        directory=tmp_path,
        acknowledged=False,
    )
    handshake = dict(
        worker_identity=worker,
        run_id="d" * 32,
        request_id=request["request_id"],
        request_sha256="c" * 64,
        snapshot={},
    )
    monkeypatch.setattr(module, "_coordinator_read", lambda *args: handshake)
    monkeypatch.setattr(module, "_coordinator_preflight", lambda *args, **kwargs: {})
    monkeypatch.setattr(module, "_coordinator_live_lease", lambda *args: None)
    monkeypatch.setattr(assembly, "_process_creation_identity", lambda *args: "child")
    context = {"store": SimpleNamespace(bind=lambda *args: {"run_id": "d" * 32})}

    def publish(*args):
        assert job["acknowledged"] is True
        assert job["run_id"] == "d" * 32

    monkeypatch.setattr(module, "_coordinator_write", publish)
    assert module._coordinator_handshake(tmp_path, request, owner, context, job) is True


def test_coordinator_reported_resource_cleanup_failure_never_completes(
    tmp_path, monkeypatch
):
    import factoryline.cli_deep_audit as module
    import factoryline.deep_audit as audit

    job = dict(
        run_id="a" * 32, directory=tmp_path, cleanup_confirmed=True, acknowledged=True
    )
    monkeypatch.setattr(
        module,
        "_coordinator_read",
        lambda *args: {
            "run_id": job["run_id"],
            "analysis_complete": False,
        },
    )
    monkeypatch.setattr(
        audit,
        "deep_run_status",
        lambda *args: {
            "analysis_complete": False,
            "gaps": [{"code": "E_CONTAINER_CLEANUP"}],
        },
    )
    with pytest.raises(ValueError, match="resource cleanup"):
        module._coordinator_completed(tmp_path, job, {"exit_code": 0})


def _coordinator_test_owner(root, module, monkeypatch):
    """Use explicit synthetic process identity for platform-neutral ingress tests."""
    import hashlib
    import os
    import time
    import factoryline.assembly_process as assembly
    from factoryline.agentic_control import CoordinatorRequestStore

    synthetic_creation = "synthetic-ingress-fixture:process-creation"
    monkeypatch.setattr(
        assembly, "_process_creation_identity", lambda pid: synthetic_creation
    )
    owner = dict(
        pid=os.getpid(),
        creation=synthetic_creation,
        session_nonce="a" * 32,
        runtime_sha256=module._coordinator_runtime_identity(),
        workspace_sha256=hashlib.sha256(str(root.resolve()).encode()).hexdigest(),
    )
    store = CoordinatorRequestStore(root)
    store.acquire(owner, 60, time.monotonic())
    return owner, dict(store=store, stop=False, expires_at=time.monotonic() + 60)


@pytest.mark.parametrize(
    "fault",
    [
        "creation",
        "missing_creation",
        "observed_unknown",
        "pid",
        "nonce",
        "runtime",
        "expired",
        "workspace",
    ],
)
def test_coordinator_stale_owner_rejects_before_child(tmp_path, monkeypatch, fault):
    import factoryline.cli_deep_audit as module
    import factoryline.assembly_process as assembly
    import subprocess

    owner, context = _coordinator_test_owner(tmp_path, module, monkeypatch)
    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected child")
    )
    if fault == "creation":
        owner["creation"] = "wrong"
    elif fault == "missing_creation":
        owner["creation"] = None
    elif fault == "observed_unknown":
        monkeypatch.setattr(assembly, "_process_creation_identity", lambda pid: None)
    elif fault == "expired":
        context["expires_at"] = 0
    else:
        key = {
            "pid": "pid",
            "nonce": "session_nonce",
            "runtime": "runtime_sha256",
            "workspace": "workspace_sha256",
        }[fault]
        owner[key] = -1 if fault == "pid" else "wrong"
    with pytest.raises(ValueError):
        module.dispatch_deep_audit_request(tmp_path, request, owner, context)


def test_coordinator_unsigned_audit_rejects_before_worker(tmp_path, monkeypatch):
    import factoryline.cli_deep_audit as module
    import subprocess

    owner, context = _coordinator_test_owner(tmp_path, module, monkeypatch)
    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected child")
    )
    with pytest.raises((ValueError, RuntimeAuditError)):
        module.dispatch_deep_audit_request(tmp_path, request, owner, context)


def test_coordinator_invalid_manifest_rejects_before_inventory(tmp_path, monkeypatch):
    import factoryline.cli_deep_audit as module
    import factoryline.deep_audit_io as audit_io

    payload = _coordinator_test_payload(tmp_path)
    monkeypatch.setattr(
        audit_io,
        "inventory_candidate",
        lambda *args: pytest.fail(
            "invalid authorization reached inventory subprocesses"
        ),
    )
    with pytest.raises((ValueError, RuntimeAuditError)):
        module._coordinator_preflight(tmp_path, payload)


def test_coordinator_deleted_lease_rejects_before_child(tmp_path, monkeypatch):
    import factoryline.cli_deep_audit as module
    import subprocess
    from factoryline.agentic_control import AgenticControlError

    owner, context = _coordinator_test_owner(tmp_path, module, monkeypatch)
    context["store"].release(owner)
    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = _coordinator_test_payload(tmp_path)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected child")
    )
    with pytest.raises((ValueError, AgenticControlError)):
        module.dispatch_deep_audit_request(tmp_path, request, owner, context)


@pytest.mark.parametrize("ttl", [None, 1, 300, 3600])
def test_coordinator_native_foreground_supported_or_fail_closed(
    tmp_path, monkeypatch, ttl
):
    import io
    import subprocess
    import sys
    from factoryline.cli_deep_audit import serve_deep_audit_coordinator

    requests = [_coordinator_test_request(tmp_path, op) for op in ("status", "stop")]
    requests[1]["request_id"] = "c" * 32
    stream = io.BytesIO(
        ("\n".join(json.dumps(row) for row in requests) + "\n").encode()
    )
    output = io.StringIO()
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected child")
    )
    if sys.platform not in {"win32", "linux"}:
        with pytest.raises(ValueError, match="creation identity is unavailable"):
            serve_deep_audit_coordinator(tmp_path, ttl, "a" * 32, stream, output)
        assert output.getvalue() == ""
        assert not (tmp_path / ".factory").exists()
        return
    result = serve_deep_audit_coordinator(tmp_path, ttl, "a" * 32, stream, output)
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    if ttl == 1 and any(row["state"] == "INCOMPLETE" for row in rows):
        assert all(row["state"] in {"OBSERVED", "INCOMPLETE"} for row in rows)
        assert all(
            row.get("code") == "E_COORDINATOR_REQUEST"
            for row in rows
            if row["state"] == "INCOMPLETE"
        )
        assert all(
            row["authority"] == "none" and row["release_approval"] is False
            for row in rows
        )
        return
    assert [row["state"] for row in rows] == ["OBSERVED", "STOPPED"]
    assert rows[0]["execution_available"] is False
    assert result == rows[-1]
    assert all(
        row["authority"] == "none" and row["release_approval"] is False for row in rows
    )


def test_coordinator_unknown_process_identity_fails_closed_before_lease(
    tmp_path, monkeypatch
):
    import io
    import subprocess
    import factoryline.assembly_process as assembly
    from factoryline.cli_deep_audit import serve_deep_audit_coordinator

    monkeypatch.setattr(assembly, "_process_creation_identity", lambda pid: None)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected child or fallback")
    )
    output = io.StringIO()
    raw = json.dumps(_coordinator_test_request(tmp_path)).encode() + b"\n"
    with pytest.raises(ValueError, match="creation identity is unavailable"):
        serve_deep_audit_coordinator(tmp_path, 300, "a" * 32, io.BytesIO(raw), output)
    assert output.getvalue() == ""
    assert not (tmp_path / ".factory").exists()


@pytest.mark.parametrize("ttl", [True, False, 0, 3601])
def test_coordinator_rejects_invalid_ttl_before_ingress(tmp_path, ttl):
    import io
    from factoryline.cli_deep_audit import serve_deep_audit_coordinator

    output = io.StringIO()
    with pytest.raises(ValueError):
        serve_deep_audit_coordinator(tmp_path, ttl, "a" * 32, io.BytesIO(), output)
    assert output.getvalue() == ""


@pytest.mark.parametrize("partial", [b"", b'{"operation":', b'{"value":"\xc3'])
def test_coordinator_native_open_stdin_expires_and_releases_lease(tmp_path, partial):
    import subprocess
    import sys
    import time
    import factoryline.cli_deep_audit as module
    from factoryline.agentic_control import CoordinatorRequestStore

    if sys.platform not in {"win32", "linux"}:
        pytest.skip("native pipe polling unsupported")
    package = str(Path(module.__file__).resolve().parent.parent)
    bootstrap = (
        "import sys;sys.path.insert(0," + repr(package) + ");"
        "from factoryline.cli import main;"
        "import platform;platform.platform();"
        'exec("def no_child(event,args):\\n'
        " if event=='subprocess.Popen' and '-I' in args[1]:\\n"
        "  print('UNEXPECTED_AUDIT_CHILD',file=sys.stderr,flush=True)\\n"
        "  raise RuntimeError('unexpected audit child')\");"
        "sys.addaudithook(no_child);"
        "sys.exit(main(['deep-audit','coordinator','--root',sys.argv[1],'--lease-seconds','2','--session-nonce','a'*32]))"
    )
    started = time.monotonic()
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", bootstrap, str(tmp_path.resolve())],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=tmp_path,
    )
    try:
        if partial:
            child.stdin.write(partial)
            child.stdin.flush()
        assert not child.stdin.closed
        child.wait(timeout=15)
        assert not child.stdin.closed, "the writer must remain open through expiry"
        output = child.stdout.read().decode("utf-8")
        error = child.stderr.read().decode("utf-8")
        assert child.returncode == 1, error
        assert "UNEXPECTED_AUDIT_CHILD" not in error
        rows = [json.loads(line) for line in output.splitlines()]
        assert len(rows) == 1
        assert rows[0]["state"] == "INCOMPLETE"
        assert rows[0]["code"] == "E_COORDINATOR_LEASE_EXPIRED"
        assert rows[0]["authority"] == "none"
        assert rows[0]["release_approval"] is False
        assert time.monotonic() - started < 15
        store = CoordinatorRequestStore(tmp_path)
        with store._connect() as records:
            assert records == {}, "idle expiry must release ownership without admission"
        assert not any(
            path.is_dir()
            for path in (tmp_path / ".factory/deep-runs/requests").glob("coordinator-*")
        )
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stdin.close()
        child.stdout.close()
        child.stderr.close()


@pytest.mark.parametrize("phase", ["lease_only", "admitted"])
@pytest.mark.parametrize("exit_mode", ["normal", "crash"])
def test_coordinator_native_restart_reconciles_expired_lease(
    tmp_path, phase, exit_mode
):
    """A fresh coordinator retires only safe dead-owner state, without replay."""
    import json
    import sys
    import time
    import factoryline.cli_deep_audit as module
    from factoryline.agentic_control import AgenticControlError, CoordinatorRequestStore
    from factoryline.assembly_process import _process_identity_absent, run_cli_detailed
    from factoryline.deep_audit_io import read_run_json

    if sys.platform not in {"win32", "linux"}:
        pytest.skip("native process identity unsupported")
    package = str(Path(module.__file__).resolve().parent.parent)
    nonce, request_id = "a" * 32, "e" * 32
    bootstrap = r"""import io,json,os,sys,time
sys.path.insert(0,sys.argv[1])
from factoryline.cli_deep_audit import _coordinator_owner,serve_deep_audit_coordinator
from factoryline.agentic_control import AgenticControlError,CoordinatorRequestStore
root,phase,mode=sys.argv[2:5]; nonce="a"*32; request_id="e"*32; request_sha="f"*64
owner=_coordinator_owner(root,nonce); store=CoordinatorRequestStore(root)
if mode in {"write","crash_write"}:
 lease=store.acquire(owner,1,time.monotonic())
 if phase=="admitted": store.admit(nonce,request_id,request_sha,owner)
 print(json.dumps({"owner":owner,"expires_monotonic":lease["expires_monotonic"]}),flush=True)
 if mode=="crash_write": os._exit(73)
else:
 import factoryline.cli_deep_audit as cli
 import factoryline.assembly_process as assembly
 events=[]
 def forbidden(*args,**kwargs): events.append("forbidden"); raise AssertionError("unexpected dispatch or signal")
 cli.dispatch_deep_audit_request=forbidden
 assembly._terminate_unit=forbidden
 assembly._emergency_terminate=forbidden
 try: serve_deep_audit_coordinator(root,1,nonce,io.BytesIO(b""),io.StringIO())
 except AgenticControlError as error: code=error.code
 else: code="started"
 print(json.dumps({"code":code,"owner":owner,"forbidden_calls":events}),flush=True)
"""
    observed = []

    def started(row):
        observed.append(dict(row))

    def launch(mode):
        return run_cli_detailed(
            sys.executable,
            ["-I", "-c", bootstrap, package, str(tmp_path.resolve()), phase, mode],
            tmp_path,
            timeout=20,
            started_observer=started,
        )

    original = launch("crash_write" if exit_mode == "crash" else "write")
    assert original["cleanup_confirmed"] and original["streams_closed"]
    if exit_mode == "crash":
        assert original["exit_code"] == 73
        assert not original["ok"]
    else:
        assert original["ok"]
    written = json.loads(original["stdout"].decode("utf-8"))
    old_owner = written["owner"]
    assert observed[-1]["pid"] == old_owner["pid"]
    assert observed[-1]["creation"] == old_owner["creation"]
    store = CoordinatorRequestStore(tmp_path)

    def metadata_rows():
        snapshot = read_run_json(store.path.parent, store.path.name)
        return {
            key: store._decode(key, value) for key, value in snapshot["rows"].items()
        }

    metadata = metadata_rows()
    lease_before = metadata["lease"]
    assert lease_before["owner_identity"] == old_owner
    key = nonce + ":" + request_id
    row_before = metadata.get(key)
    if phase == "admitted":
        assert row_before is not None and row_before["state"] == "ADMITTED"
        assert row_before["run_id"] is None and row_before["worker_identity"] is None
    else:
        assert row_before is None

    while time.monotonic() < written["expires_monotonic"]:
        time.sleep(max(0, min(0.02, written["expires_monotonic"] - time.monotonic())))
    restarted = launch("restart")
    assert (
        restarted["ok"]
        and restarted["cleanup_confirmed"]
        and restarted["streams_closed"]
    )
    result = json.loads(restarted["stdout"].decode("utf-8"))
    new_owner = result["owner"]
    assert result["code"] == "started"
    assert result["forbidden_calls"] == []
    assert observed[-1]["pid"] == new_owner["pid"]
    assert observed[-1]["creation"] == new_owner["creation"]
    assert (new_owner["pid"], new_owner["creation"]) != (
        old_owner["pid"],
        old_owner["creation"],
    )

    assert _process_identity_absent(old_owner["pid"], old_owner["creation"])
    after = metadata_rows()
    if phase == "admitted":
        # A dead PID does not prove cleanup for an admitted request. Preserve
        # its history and block new admission without signalling or replay.
        assert "lease" not in after
        assert after[key] == row_before | dict(
            state="INCOMPLETE", cleanup_confirmed=False
        )
        assert after[key]["owner_identity"] == old_owner
        assert after[key]["run_id"] is None
        verified = CoordinatorRequestStore(
            tmp_path, process_absent=_process_identity_absent
        )
        verified.acquire(new_owner, 1, time.monotonic())
        with pytest.raises(AgenticControlError) as error:
            verified.admit(nonce, "9" * 32, "8" * 64, new_owner)
        assert error.value.code == "E_COORDINATOR_BUSY"
        assert metadata_rows()[key] == after[key]
        verified.release(new_owner)
    else:
        # With no admitted request to protect, a proven-exited owner may be
        # retired; the restarted idle coordinator releases its own lease.
        assert after == {}
        store.acquire(new_owner, 1, time.monotonic())
        store.release(new_owner)


@pytest.mark.parametrize("text_stream", [False, True])
def test_coordinator_readline_memory_coalesced_utf8_and_eof(text_stream):
    import io
    import time
    from factoryline.cli_deep_audit import _coordinator_readline, _coordinator_line

    raw = '{"value":"é"}\n{"value":2}\n'
    stream = io.StringIO(raw) if text_stream else io.BytesIO(raw.encode())
    context = dict(expires_at=time.monotonic() + 5)
    assert _coordinator_line(_coordinator_readline(stream, context)) == {"value": "é"}
    assert _coordinator_line(_coordinator_readline(stream, context)) == {"value": 2}
    assert _coordinator_readline(stream, context) in (b"", "")


@pytest.mark.parametrize("extra", [False, True])
def test_coordinator_readline_exact_and_over_byte_boundary(extra):
    import io
    import time
    from factoryline.cli_deep_audit import _coordinator_readline, _coordinator_line

    raw = b'{"value":"ok"}'
    raw += b" " * (65536 - len(raw))
    if extra:
        raw += b" "
    line = _coordinator_readline(io.BytesIO(raw), dict(expires_at=time.monotonic() + 5))
    if extra:
        with pytest.raises(ValueError):
            _coordinator_line(line)
    else:
        assert _coordinator_line(line) == {"value": "ok"}


def test_coordinator_readline_native_fragmented_utf8_and_coalesced_lines():
    import os
    import sys
    import threading
    import time
    from factoryline.cli_deep_audit import _coordinator_readline, _coordinator_line

    if sys.platform not in {"win32", "linux"}:
        pytest.skip("native pipe polling unsupported")
    reader_fd, writer_fd = os.pipe()
    reader = os.fdopen(reader_fd, "rb", buffering=0)
    writer = os.fdopen(writer_fd, "wb", buffering=0)

    def fragmented_writer():
        for part in (b'{"value":"\xc3', b'\xa9"}', b'\n{"value":2}\n'):
            writer.write(part)
            time.sleep(0.025)
        writer.close()

    thread = threading.Thread(target=fragmented_writer)
    thread.start()
    try:
        context = dict(expires_at=time.monotonic() + 5)
        assert _coordinator_line(_coordinator_readline(reader, context)) == {
            "value": "é"
        }
        assert _coordinator_line(_coordinator_readline(reader, context)) == {"value": 2}
        assert _coordinator_readline(reader, context) == b""
    finally:
        thread.join(timeout=5)
        reader.close()
        assert not thread.is_alive()


@pytest.mark.parametrize("prefix", ["", "example/adapter@"])
def test_full_local_image_id_and_repository_digest_are_immutable_pins(prefix):
    from factoryline.deep_audit_contract import _validate_lane_image

    assert _validate_lane_image({"image": prefix + "sha256:" + "a" * 64}) is None


def _rechain_action_test_events(directory, events, state, digest, write_run_json):
    previous = None
    for index, event in enumerate(events, 1):
        event["sequence"], event["previous_sha256"] = index, previous
        write_run_json(directory, f"event-{index:05d}.json", event)
        previous = digest(event)
    state.update(sequence=len(events), event_sha256=previous, analysis_complete=True)
    write_run_json(directory, "state.json", state)


def _observed_action_status(
    module, root, directory, run_id, read_run_json, digest, write_run_json
):
    state = read_run_json(directory, "state.json")
    rows = {row["action_id"]: row for row in state["lanes"]}
    for row in rows.values():
        row.update(state="OBSERVED", gaps=[])
    state.update(analysis_complete=True, gaps=[])
    events = [
        read_run_json(directory, f"event-{index:05d}.json")
        for index in range(1, state["sequence"] + 1)
    ]
    for event in events:
        if event["kind"] == "lane_completed":
            event["details"].update(
                module._action_terminal(rows[event["details"]["action_id"]])
            )
    events[-1]["details"]["analysis_complete"] = True
    _rechain_action_test_events(directory, events, state, digest, write_run_json)
    return module.deep_run_status(root, run_id), state, events


def _damage_action_test_events(damage, events, start, terminal):
    if damage == "missing_start":
        start["kind"] = "unrecognized"
    elif damage == "missing_terminal":
        terminal["kind"] = "unrecognized"
    elif damage == "duplicate":
        import copy

        events.append(copy.deepcopy(terminal))
    elif damage == "unknown":
        start["details"]["action_id"] = "f" * 64
    elif damage == "identity":
        start["details"]["family"] = "wrong-family"
    elif damage == "hash":
        terminal["details"]["report_sha256"] = "0" * 64
    else:
        events.remove(start)
        events.insert(events.index(terminal) + 1, start)


@pytest.mark.parametrize(
    "image",
    [
        "example/adapter:latest",
        "example/adapter:v1",
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 64 + ":tag",
        "sha256:" + "a" * 64 + "\n",
        "a" * 64,
    ],
)
def test_mutable_or_ambiguous_image_references_are_rejected(image):
    from factoryline.deep_audit_contract import _validate_lane_image

    code = "E_FIELD" if "\n" in image else "E_IMAGE_PIN"
    with pytest.raises(RuntimeAuditError, match=code):
        _validate_lane_image({"image": image})


def fixture(tmp_path, mutate=lambda p: None):
    bindings = {}
    for name, raw in (
        ("app.py", b"one\ntwo"),
        ("scan.json", b'{"scan":1}'),
        ("canary.json", b'{"scan":2}'),
    ):
        (tmp_path / name).write_bytes(raw)
        bindings[name] = {"path": name, "sha256": sha256_bytes(raw)}
    sources = [{**bindings["app.py"], "bytes": 7}]
    now = datetime.now(timezone.utc)
    plan = {
        "schema": PLAN_SCHEMA,
        "id": "audit",
        "candidate_sha256": digest(sources),
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "sources": sources,
        "analyzers": [
            {
                "id": "s",
                "driver": "Example",
                "version": "1",
                "report": bindings["scan.json"],
                "canary_report": bindings["canary.json"],
            }
        ],
        "rules": [
            {
                "id": "r",
                "obligation_id": "no-leak",
                "category": "memory",
                "severity": "high",
                "aliases": [{"analyzer_id": "s", "rule_id": "leak"}],
                "max_new": 0,
                "max_total": 0,
                "min_trace_steps": 2,
                "require_source_sink": True,
                "allowed_suppressions": [],
                "origin": "human_confirmed",
                "remediation": "Close owned resources",
                "consequence": "Retained memory",
            }
        ],
        "canaries": [
            {
                "id": "c",
                "analyzer_id": "s",
                "rule_id": "leak",
                "fingerprint_sha256": "a" * 64,
            }
        ],
    }
    mutate(plan)
    material = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="owner",
        identity="owner@example.test",
        issuer="https://issuer.example.test",
    )
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=Path(material["private_key"]),
        keyid=material["keyid"],
        identity=material["identity"],
        issuer=material["issuer"],
    )
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"])
    return path, trust, sha256_bytes(trust.read_bytes()), tmp_path


def test_signature_sources_and_policy_are_bound(tmp_path):
    args = fixture(tmp_path)
    checked = verify_deep_audit_plan(*args)
    assert checked["authority"] == "none"
    assert len(checked["ruleset_sha256"]) == 64
    assert checked["source_hashes"]["app.py"] == sha256_bytes(b"one\ntwo")
    (tmp_path / "scan.json").write_text("tampered")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        verify_deep_audit_plan(*args)


@pytest.mark.parametrize(
    "revocation", [{"revoked": True}, {"revoked_at": "2026-01-01T00:00:00Z"}]
)
def test_plan_rejects_revoked_signer(tmp_path, revocation):
    path, trust, _, root = fixture(tmp_path)
    value = json.loads(trust.read_text())
    value["keys"][0].update(revocation)
    trust.write_text(json.dumps(value))
    with pytest.raises(RuntimeAuditError, match="E_PLAN_SIGNER_REVOKED"):
        verify_deep_audit_plan(path, trust, sha256_bytes(trust.read_bytes()), root)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda p: p["rules"][0].update(origin="agent_proposed"), "E_RULE_AUTHORITY"),
        (
            lambda p: p["rules"][0].update(origin="observed_production"),
            "E_RULE_AUTHORITY",
        ),
        (lambda p: p["rules"][0].update(max_new=True), "E_FIELD"),
        (lambda p: p.update(candidate_sha256="b" * 64), "E_CANDIDATE_DRIFT"),
        (lambda p: p.update(canaries=[]), "E_PLAN_FIELDS"),
        (lambda p: p["canaries"][0].update(rule_id="unknown"), "E_CANARY_POLICY"),
        (
            lambda p: p["analyzers"][0].update(
                canary_report=p["analyzers"][0]["report"]
            ),
            "E_DUPLICATE_ID",
        ),
        (lambda p: p.update(expires_at="2000-01-01T00:00:00+00:00"), "E_PLAN_EXPIRED"),
        (lambda p: p.update(issued_at="2020-01-01T00:00:00"), "E_TIME"),
        (lambda p: p.update(unapproved_exception=True), "E_PLAN_FIELDS"),
    ],
)
def test_signed_bad_contract_is_rejected(tmp_path, mutate, code):
    args = fixture(tmp_path, mutate)
    with pytest.raises(RuntimeAuditError, match=code):
        verify_deep_audit_plan(*args)


def test_wrong_pin_and_forged_signature(tmp_path):
    path, trust, pin, root = fixture(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_TRUST_ROOT_DRIFT"):
        verify_deep_audit_plan(path, trust, "0" * 64, root)
    envelope = json.loads(path.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    path.write_text(json.dumps(envelope))
    with pytest.raises((EnterpriseReceiptError, RuntimeAuditError)):
        verify_deep_audit_plan(path, trust, pin, root)


def test_verified_contract_drives_real_report_normalization(tmp_path):
    from test_deep_audit_sarif import report
    from factoryline.deep_audit_sarif import normalize_sarif

    def bind_reports(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            raw = json.dumps(payload).encode()
            (tmp_path / name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest(
            {"partialFingerprints:primary/v1": "canary_report"}
        )

    verified = verify_deep_audit_plan(*fixture(tmp_path, bind_reports))
    analyzer = verified["plan"]["analyzers"][0]
    target = normalize_sarif(
        tmp_path, analyzer["report"], analyzer, verified["source_hashes"]
    )
    canary = normalize_sarif(
        tmp_path, analyzer["canary_report"], analyzer, verified["source_hashes"]
    )
    assert target["findings"][0]["rule_id"] == "leak"
    assert (
        canary["findings"][0]["native_fingerprint_sha256"]
        == verified["plan"]["canaries"][0]["fingerprint_sha256"]
    )
    assert target["authority"] == "none"


# Execution fixtures deliberately use local test keys and synthetic scanner output.
# They test orchestration and rejection behavior, never real security coverage.
def execution_fixture(tmp_path):
    import subprocess
    from factoryline.deep_audit_io import inventory_candidate

    root = tmp_path / "workspace"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "app.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    control = tmp_path / "control"
    control.mkdir()
    material = {}
    keys = []
    for role in ("implementer", "reviewer", "coordinator"):
        entry = generate_key_material(
            out_dir=control / role,
            keyid=role,
            identity=f"{role}@example.test",
            issuer="https://test.invalid",
        )
        material[role] = entry
        key = json.loads(Path(entry["trust_root"]).read_text())["keys"][0]
        key["roles"] = [role]
        keys.append(key)
    trust = control / "trust.json"
    template = json.loads(Path(material["coordinator"]["trust_root"]).read_text())
    template["keys"] = keys
    trust.write_text(json.dumps(template), encoding="utf-8")
    (root / "clean.py").write_text("print('clean')\n", encoding="utf-8")
    inventory = inventory_candidate(root)
    assert inventory["state"] == "COMPLETE"
    families = {
        "codeql": "static",
        "syft": "dependencies",
        "osv": "dependencies",
        "gitleaks": "secrets",
        "trivy": "configuration",
        "runtime": "runtime",
        "atheris": "fuzz",
    }
    lanes = []
    for engine, family in families.items():
        mode = "interprocedural-full" if family == "static" else "full"
        lanes.append(
            {
                "id": engine,
                "engine": engine,
                "family": family,
                "image": f"example.test/{engine}@sha256:" + "a" * 64,
                "argv": ["/opt/factory/bin/audit-adapter", engine, "--mode", mode],
                "report": "report.json",
                "coverage": "coverage.json",
                "challenge_report": "challenges.json",
                "languages": ["python"],
                "mode": mode,
                "timeout_seconds": 10,
                "memory_mib": 128,
                "tool_version": "1.0",
                "ruleset_sha256": "b" * 64,
                **({"rule_ids": ["fixture-detection"]} if engine == "gitleaks" else {}),
            }
        )
    plan = {
        "schema": "factory.deep-execution.v1",
        "candidate_sha256": inventory["candidate_sha256"],
        "implementer_id": "implementer@example.test",
        "implementer_keyid": "implementer",
        "reviewer_identity": "reviewer@example.test",
        "reviewer_keyid": "reviewer",
        "coordinator_identity": "coordinator@example.test",
        "coordinator_keyid": "coordinator",
        "trust_root_sha256": sha256_bytes(trust.read_bytes()),
        "lanes": lanes,
        "obligations": [
            {
                "id": engine,
                "engine": engine,
                "detector_rule_id": "fixture-detection",
                "family": family,
                "paths": ["app.py", "clean.py"],
                "requirements": ["app.py"],
                "remediation": "Exercise and verify the boundary.",
            }
            for engine, family in families.items()
        ],
    }
    for obligation in plan["obligations"]:
        lane = next(item for item in lanes if item["engine"] == obligation["engine"])
        obligation["challenges"] = []
        for kind in ("positive", "negative", "mutation"):
            report = execution_challenge(lane, inventory, kind)
            obligation["challenges"].append(
                {
                    "kind": kind,
                    "fixture_path": "clean.py" if kind == "negative" else "app.py",
                    "fixture_sha256": report["fixture_sha256"],
                    "expected_report_sha256": digest(report),
                    "expected_exit_code": 0,
                }
            )
    manifest = control / "manifest.json"
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    pin = sha256_bytes(manifest.read_bytes())
    now = datetime.now(timezone.utc)
    payload = {
        "schema": "factory.deep-execution-authorization.v1",
        "manifest_sha256": pin,
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_content_sha256": digest(plan),
        "adapter_images": {lane["id"]: lane["image"] for lane in lanes},
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=50)).isoformat(),
        "authority": "none",
    }
    authorization = execution_sign(
        control / "authorization.json", payload, material["coordinator"]
    )
    return root, manifest, pin, authorization, trust, plan, inventory, material


def _coordinator_signed_fixture(tmp_path):
    import time
    import factoryline.cli_deep_audit as module
    from factoryline.agentic_control import CoordinatorRequestStore
    from factoryline.deep_audit_io import inventory_candidate

    root, manifest, pin, authorization, trust, _, inventory, material = (
        execution_fixture(tmp_path)
    )
    public = root / ".factory/deep-runs/requests/integration"
    public.mkdir(parents=True)
    bindings = {}
    for name, source in (
        ("manifest", manifest),
        ("authorization", authorization),
        ("trust_root", trust),
    ):
        target = public / source.name
        target.write_bytes(source.read_bytes())
        assert target.read_bytes() == source.read_bytes()
        bindings[name] = target.relative_to(root).as_posix()
    assert inventory_candidate(root) == inventory
    assert all(
        not Path(entry["private_key"]).is_relative_to(root)
        for entry in material.values()
    )
    request = _coordinator_test_request(root, "audit")
    request["payload"] = dict(
        bindings,
        manifest_sha256=pin,
        trust_root_sha256=sha256_bytes(trust.read_bytes()),
    )
    owner = module._coordinator_owner(root, request["session_nonce"])
    store = CoordinatorRequestStore(root)
    lease = store.acquire(owner, 45, time.monotonic())
    context = dict(
        store=store,
        owner=owner,
        root=root,
        ttl=45,
        expires_at=lease["expires_monotonic"],
        stop=False,
        job=None,
    )
    return root, request, owner, context, inventory


@pytest.mark.parametrize("stop_child", [False, True])
def test_coordinator_native_signed_child_handshake_and_cleanup(
    tmp_path, monkeypatch, stop_child
):
    import os
    import sys
    import time
    import factoryline.cli_deep_audit as module
    from factoryline.deep_audit import deep_run_status
    from factoryline.deep_audit_io import inventory_candidate
    from factoryline.agentic_control import AgenticControlError

    if sys.platform not in {"win32", "linux"}:
        if os.environ.get("FACTORY_REQUIRE_NATIVE_SIGNED_LIFECYCLE") == "1":
            pytest.fail("selected CI host does not support native process identity")
        pytest.skip("native process creation identity unsupported")
    root, request, owner, context, inventory = _coordinator_signed_fixture(tmp_path)
    # Run the signed transport against explicit unavailable-engine evidence.
    monkeypatch.setenv("PATH", _coordinator_transport_path(tmp_path))
    observed_handshakes = []
    try:
        admitted = module.dispatch_deep_audit_request(root, request, owner, context)
        assert admitted["state"] == "ADMITTED"
        job = context["job"]
        other = dict(request, request_id="c" * 32)
        with pytest.raises(AgenticControlError, match="retained request"):
            module.dispatch_deep_audit_request(root, other, owner, context)
        deadline = time.monotonic() + 50
        while job["thread"].is_alive() and time.monotonic() < deadline:
            # Direct dispatch must service the same active lease as the server.
            # Renewal deliberately cannot revive an already expired owner.
            assert time.monotonic() < context["expires_at"]
            module._coordinator_renew(context)
            directory = job.get("directory")
            if directory:
                assert not (directory / "input.json").exists()
            if (
                directory
                and not observed_handshakes
                and (directory / "handshake.json").exists()
            ):
                try:
                    observed_handshakes.append(
                        module._coordinator_read(root, directory, "handshake.json")
                    )
                except OSError:
                    pass
            if stop_child and observed_handshakes:
                stop = _coordinator_test_request(root, "stop")
                stop["request_id"] = "d" * 32
                result = module.dispatch_deep_audit_request(root, stop, owner, context)
                assert result["state"] == "STOPPED"
                assert result["cleanup_confirmed"] is True
                break
            time.sleep(0.01)
        job["thread"].join(timeout=55)
        assert not job["thread"].is_alive()
        assert observed_handshakes, "fresh child never produced its sealed handshake"
        handshake = observed_handshakes[0]
        assert handshake["worker_identity"]["pid"] != os.getpid()
        assert handshake["worker_identity"]["creation"]
        assert handshake["worker_identity"]["pid"] == job["observed"]["pid"]
        assert len(handshake["run_id"]) == 32
        assert handshake["request_id"] == request["request_id"]
        assert job["cleanup_confirmed"] is True, (
            job.get("failure_phase"),
            job.get("failure_code"),
        )
        assert not job["directory"].exists()
        row = context["store"].read(request["session_nonce"], request["request_id"])
        assert row["state"] in {"INCOMPLETE", "ABANDONED"}
        assert row["cleanup_confirmed"] is True
        if not stop_child:
            assert job["acknowledged"] is True
        assert row["run_id"] == handshake["run_id"]
        evidence = deep_run_status(root, handshake["run_id"])
        assert evidence["analysis_complete"] is False
        assert inventory_candidate(root) == inventory
        if not stop_child:
            duplicate = module.dispatch_deep_audit_request(
                root, request, owner, context
            )
            assert duplicate["state"] == "INCOMPLETE"
            assert duplicate["run_id"] == row["run_id"]
            assert context["job"] is job
        status = module._coordinator_status(_coordinator_test_request(root), context)
        assert status["audit_state"] == row["state"]
        assert status["authority"] == "none" and status["release_approval"] is False
        phases = {p["phase"]: p for p in status["phase_timings"]["phases"]}
        assert set(phases) == {"child_launch", "child_wait", "child_cleanup"}
        assert all(p["calls"] == p["completed"] == 1 for p in phases.values())
        assert all(p["elapsed_ms"] >= 0 for p in phases.values())
        assert status["phase_timings"]["status"] == "complete"
        assert status["execution_available"] is False
        assert str(root) not in json.dumps(status["phase_timings"])
    finally:
        assert module._coordinator_shutdown(context)
        context["store"].release(owner)


@pytest.mark.parametrize("fail", [False, True])
def test_coordinator_phase_recorders_are_job_local_private_and_preserve_errors(
    tmp_path, monkeypatch, fail
):
    import threading
    import factoryline.cli_deep_audit as module
    from factoryline.ops_telemetry import _measure_call, _phase_telemetry

    secret = "private-arguments-output-and-exception"
    error = RuntimeError(secret)
    errors, jobs = [], []

    def execute(*args):
        _measure_call("child_launch", lambda: secret)
        assert "phase_timings" not in args[-1]
        try:

            def wait():
                if fail:
                    raise error
                return secret

            _measure_call("child_wait", wait)
        finally:
            _measure_call("child_cleanup", lambda: None)

    def worker(job):
        try:
            module._coordinator_execute(tmp_path, {}, {}, {}, job)
        except RuntimeError as exc:
            errors.append(exc)

    monkeypatch.setattr(module, "_coordinator_execute_job", execute)
    with _phase_telemetry(0) as parent:
        _measure_call("source_read", lambda: secret)
        for _ in range(2):
            job = {}
            thread = threading.Thread(target=worker, args=(job,))
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive()
            jobs.append(job)
        assert [p["phase"] for p in parent.snapshot()["phases"]] == ["source_read"]
    assert errors == ([error, error] if fail else [])
    for job in jobs:
        telemetry = job["phase_timings"]
        assert set(telemetry) == {
            "status",
            "phases",
            "dropped_calls",
            "dropped_phase_names",
        }
        assert telemetry["status"] == ("incomplete" if fail else "complete")
        assert telemetry["dropped_calls"] == 0
        assert telemetry["dropped_phase_names"] == []
        assert secret not in json.dumps(telemetry) and str(tmp_path) not in json.dumps(
            telemetry
        )
        phases = {p["phase"]: p for p in telemetry["phases"]}
        assert set(phases) == {"child_launch", "child_wait", "child_cleanup"}
        assert all(p["calls"] == 1 and p["elapsed_ms"] >= 0 for p in phases.values())
        assert phases["child_wait"]["incomplete"] == int(fail)
    assert jobs[0]["phase_timings"] is not jobs[1]["phase_timings"]


def test_coordinator_runtime_identity_binds_loaded_telemetry(monkeypatch):
    import factoryline.cli_deep_audit as module
    import factoryline.ops_telemetry as telemetry

    before = module._coordinator_runtime_identity()
    assert before == module._coordinator_runtime_identity()
    monkeypatch.setattr(
        telemetry._PhaseTelemetry, "record", lambda *args, **kwargs: None
    )
    assert before != module._coordinator_runtime_identity()


@pytest.mark.parametrize("fault", ["bad_ack", "candidate_drift"])
def test_coordinator_native_private_worker_rejects_before_lanes(tmp_path, fault):
    """Real private worker only: the test, not a dispatcher, supplies the ACK."""
    import sys
    import factoryline.cli_deep_audit as module
    from factoryline.assembly_process import run_cli_detailed
    from factoryline.deep_audit import deep_run_status
    from factoryline.deep_audit_io import digest, read_run_json, run_directory

    if sys.platform not in {"win32", "linux"}:
        pytest.skip("native process creation identity unsupported")
    root, request, owner, context, _ = _coordinator_signed_fixture(tmp_path)
    directory = module._coordinator_control_directory(root)
    snapshot = module._coordinator_preflight(root, request["payload"])
    config = dict(
        request=request,
        request_sha256=digest(request),
        snapshot=snapshot,
        expires_at=context["expires_at"],
    )
    observed, handshakes = [], []

    def heartbeat():
        if handshakes or not (directory / "handshake.json").exists():
            return True
        handshake = module._coordinator_read(root, directory, "handshake.json")
        handshakes.append(handshake)
        if fault == "candidate_drift":
            (root / "app.py").write_text(
                "print('changed before ACK')\n", encoding="utf-8"
            )
        seal = "0" * 64 if fault == "bad_ack" else digest(handshake)
        module._coordinator_write(
            root, directory, "ack.json", {"handshake_sha256": seal}
        )
        return True

    try:
        result = run_cli_detailed(
            sys.executable,
            module._coordinator_worker_args(root, directory, config),
            root,
            timeout=40,
            started_observer=observed.append,
            heartbeat=heartbeat,
        )
        assert result["exit_code"] not in (0, None), result
        assert result["cleanup_confirmed"] is True
        assert result["streams_closed"] is True
        assert len(handshakes) == len(observed) == 1
        handshake = handshakes[0]
        assert handshake["worker_identity"]["pid"] == observed[0]["pid"]
        expected = (
            "worker acknowledgement differs"
            if fault == "bad_ack"
            else "signed candidate inventory differs"
        )
        assert expected in result["output"]
        status = deep_run_status(root, handshake["run_id"])
        assert status["analysis_complete"] is False
        events_dir = run_directory(root, handshake["run_id"])
        events = [
            read_run_json(events_dir, f"event-{index:05d}.json")
            for index in range(1, status["sequence"] + 1)
        ]
        assert any(event["kind"] == "run_started" for event in events)
        assert not any(event["kind"] == "lane_started" for event in events)
        assert not (directory / "done.json").exists()
    finally:
        module._coordinator_remove_control(root, directory)
        context["store"].release(owner)


@pytest.mark.parametrize(
    "field", ["run_id", "request_id", "request_sha256", "snapshot", "extra"]
)
def test_coordinator_handshake_rejects_wrong_binding(tmp_path, field):
    import factoryline.cli_deep_audit as module

    request = _coordinator_test_request(tmp_path, "audit")
    job = dict(request_sha256="c" * 64, snapshot={"candidate_sha256": "d" * 64})
    handshake = dict(
        worker_identity={},
        run_id="e" * 32,
        request_id=request["request_id"],
        request_sha256=job["request_sha256"],
        snapshot=job["snapshot"],
    )
    module._coordinator_verify_handshake(request, job, handshake)
    handshake[field] = "invalid"
    with pytest.raises(ValueError):
        module._coordinator_verify_handshake(request, job, handshake)


def test_coordinator_unit_preflight_crosses_lease_before_admission(
    tmp_path, monkeypatch
):
    """Synthetic unit boundary, not native child-execution evidence."""
    from types import SimpleNamespace
    from factoryline.agentic_control import AgenticControlError
    import factoryline.cli_deep_audit as module

    request = _coordinator_test_request(tmp_path, "audit")
    request["payload"] = {}
    context = dict(stop=False, expires_at=float("inf"))
    context["store"] = SimpleNamespace(
        admit=lambda *a: pytest.fail("expired request admitted"),
        read=lambda *a: (_ for _ in ()).throw(
            AgenticControlError("E_COORDINATOR_REQUEST", "request not found")
        ),
    )

    def preflight(*args):
        context["expires_at"] = 0
        return {"runtime_sha256": "c" * 64}

    monkeypatch.setattr(module, "_coordinator_preflight", preflight)
    monkeypatch.setattr(module, "_coordinator_runtime_identity", lambda: "c" * 64)
    with pytest.raises(ValueError, match="live ownership"):
        module._coordinator_admit(
            tmp_path, request, {"runtime_sha256": "c" * 64}, context
        )
    assert "job" not in context


def test_coordinator_unit_prelaunch_bounds_failure_cleans_control(
    tmp_path, monkeypatch
):
    """Unit fault injection before subprocess launch; no native proof claim."""
    from types import SimpleNamespace
    import time
    import factoryline.cli_deep_audit as module
    import factoryline.assembly_process as assembly

    request = _coordinator_test_request(tmp_path, "audit")
    job = dict(
        request_sha256="c" * 64,
        snapshot={},
        run_id=None,
        cleanup_confirmed=False,
        launch_attempted=False,
    )
    recorded = []
    context = dict(
        expires_at=time.monotonic() + 30,
        store=SimpleNamespace(abandon=lambda *args: recorded.append(args)),
    )

    def bounded_args(*args):
        raise ValueError("bounded argv rejected")

    monkeypatch.setattr(module, "_coordinator_worker_args", bounded_args)
    monkeypatch.setattr(module, "_coordinator_check_owner", lambda *args: None)
    monkeypatch.setattr(
        assembly, "run_cli_detailed", lambda *a, **k: pytest.fail("unexpected child")
    )
    module._coordinator_execute(tmp_path, request, {}, context, job)
    assert job["launch_attempted"] is False
    assert job["cleanup_confirmed"] is True
    assert job["phase_timings"] == {
        "status": "not_observed",
        "phases": [],
        "dropped_calls": 0,
        "dropped_phase_names": [],
    }
    assert not job["directory"].exists()
    assert recorded == [
        (request["session_nonce"], request["request_id"], "c" * 64, True)
    ]


def test_coordinator_unit_done_cannot_override_authoritative_incomplete(
    tmp_path, monkeypatch
):
    """A mocked positive worker claim must not promote incomplete evidence."""
    import factoryline.cli_deep_audit as module
    import factoryline.deep_audit as audit

    run_id = "e" * 32
    job = dict(
        run_id=run_id, directory=tmp_path, cleanup_confirmed=True, acknowledged=True
    )
    monkeypatch.setattr(
        module,
        "_coordinator_read",
        lambda *args: dict(run_id=run_id, analysis_complete=True),
    )
    observations = []

    def authoritative(root, observed_run):
        observations.append((root, observed_run))
        return dict(state="INCOMPLETE", analysis_complete=False)

    monkeypatch.setattr(audit, "deep_run_status", authoritative)
    assert module._coordinator_completed(tmp_path, job, {"exit_code": 0}) is False
    assert observations == [(tmp_path, run_id)]


def test_coordinator_unit_control_cleanup_retries_sharing_violation(
    tmp_path, monkeypatch
):
    """Synthetic sharing violation exercises bounded cleanup retry only."""
    import factoryline.cli_deep_audit as module

    directory = module._coordinator_control_directory(tmp_path)
    original = module._coordinator_unlink_control
    attempts = []

    def transient(root, path):
        attempts.append(path)
        if len(attempts) == 1:
            raise PermissionError("synthetic reader")
        return original(root, path)

    monkeypatch.setattr(module, "_coordinator_unlink_control", transient)
    module._coordinator_remove_control(tmp_path, directory)
    assert attempts == [directory, directory]
    assert not directory.exists()


def execution_sign(path, payload, key):
    envelope = sign_payload(
        payload,
        payload_type=f"application/vnd.{payload['schema']}+json",
        private_key_path=Path(key["private_key"]),
        keyid=key["keyid"],
        identity=key["identity"],
        issuer=key["issuer"],
    )
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path


def execution_native(lane, inventory, detected=False):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    rule = "fixture-detection"
    if lane["engine"] in {"codeql", "gitleaks", "trivy", "semgrep"}:
        result = {
            "ruleId": rule,
            "level": "error",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": lane["engine"],
                            "version": lane["tool_version"],
                        }
                    },
                    "invocations": [{"executionSuccessful": True}],
                    "results": [result] if detected else [],
                }
            ],
        }
    if lane["engine"] == "syft":
        return {
            "artifacts": [
                {
                    "id": rule if detected else "ordinary-component",
                    "name": "fixture",
                    "version": "1.0",
                    "type": "python",
                    "locations": [{"path": "/src/" + path} for path in sources],
                }
            ],
            "descriptor": {"name": "syft", "version": "1.0"},
            "schema": {"version": "16.0.0"},
            "source": {"type": "directory", "target": "/src"},
        }
    if lane["engine"] == "osv":
        return {
            "results": [
                {
                    "source": {"path": path},
                    "packages": [
                        {
                            "package": {
                                "name": "fixture",
                                "version": "1.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": rule}] if detected else [],
                        }
                    ],
                }
                for path in sources
            ]
        }
    return {
        "schema": f"factory.deep-{lane['engine']}-observations.v1",
        "engine": lane["engine"],
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": {"path": "app.py", "sha256": sources["app.py"]},
        "metrics": {
            "tests": 1,
            "requests": 1,
            "executions": 1000,
            "coverage_edges": 10,
            "corpus_size": 5,
        },
        "source_coverage": {
            path: {
                "sha256": value,
                "lines_total": 1,
                "lines_covered": 1,
                "branches_total": 0,
                "branches_covered": 0,
            }
            for path, value in sources.items()
        },
        "findings": [{"rule_id": rule, "path": "app.py", "line": 1, "severity": "high"}]
        if detected
        else [],
    }


def execution_challenge(lane, inventory, kind):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    return {
        "schema": "factory.deep-challenge-observation.v1",
        "engine": lane["engine"],
        "fixture_sha256": sources["clean.py" if kind == "negative" else "app.py"],
        "detector_rule_id": "fixture-detection",
        "detector_enabled": kind != "mutation",
        "native_report": execution_native(lane, inventory, detected=kind == "positive"),
    }


def execution_bundle(lane, inventory, run_id):
    report = execution_native(lane, inventory)
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": {item["path"]: item["sha256"] for item in inventory["files"]},
        "complete": True,
        "errors": [],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "tool_version": lane["tool_version"],
        "ruleset_sha256": lane["ruleset_sha256"],
        "invocation_sha256": "d" * 64,
        "obligations": [lane["engine"]],
    }
    observations = []
    for kind in ("positive", "negative", "mutation"):
        challenge = execution_challenge(lane, inventory, kind)
        observations.append(
            {
                "obligation_id": lane["engine"],
                "kind": kind,
                "fixture_sha256": challenge["fixture_sha256"],
                "observation_sha256": digest(challenge),
                "report": challenge,
                "exit_code": 0,
            }
        )
    return {
        "schema": "factory.deep-worker.v1",
        "candidate_sha256": inventory["candidate_sha256"],
        "run_id": run_id,
        "artifacts": {
            "report.json": report,
            "coverage.json": coverage,
            "challenges.json": {
                "schema": "factory.deep-challenges.v1",
                "observations": observations,
            },
        },
    }


def test_osv_coordinator_recomputes_native_accounting_and_rejects_drift():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    },
                    {
                        "package": {
                            "name": "werkzeug",
                            "version": "0.1",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    },
                ],
            }
        ]
    }
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": required,
        "complete": True,
        "errors": [],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    assert "OSV_SOURCE_ACCOUNTING_DRIFT" not in _coverage_source_gaps(
        report, coverage, lane, required
    )

    sabotages = []
    forged = json.loads(json.dumps(coverage))
    forged["source_accounting"]["state"] = "COMPLETE_WITH_AUTHORITY"
    sabotages.append((report, forged, required))
    reordered = json.loads(json.dumps(coverage))
    reordered["source_accounting"]["sources"]["requirements.txt"]["packages"].reverse()
    sabotages.append((report, reordered, required))
    count_changed = json.loads(json.dumps(coverage))
    count_changed["source_accounting"]["sources"]["requirements.txt"][
        "package_count"
    ] += 1
    sabotages.append((report, count_changed, required))
    identity_report = json.loads(json.dumps(report))
    identity_report["results"][0]["packages"][0]["package"]["version"] = "9.9"
    identity_coverage = json.loads(json.dumps(coverage))
    identity_coverage["report_sha256"] = digest(identity_report)
    sabotages.append((identity_report, identity_coverage, required))
    changed_required = {"requirements.txt": "b" * 64}
    hash_coverage = json.loads(json.dumps(coverage))
    hash_coverage["sources"] = changed_required
    hash_coverage["report_sha256"] = digest(report)
    sabotages.append((report, hash_coverage, changed_required))

    for altered_report, altered_coverage, altered_required in sabotages:
        gaps = _coverage_source_gaps(
            altered_report, altered_coverage, lane, altered_required
        )
        assert "OSV_SOURCE_ACCOUNTING_DRIFT" in gaps


def test_osv_coordinator_keeps_synthetic_empty_result_incomplete():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {"results": []}
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": required,
        "complete": False,
        "errors": [
            "NATIVE_SOURCE_ACCOUNTING_REQUIRED",
            "NATIVE_CHALLENGES_REQUIRED",
        ],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    gaps = _coverage_source_gaps(report, coverage, lane, required)
    assert "OSV_SOURCE_ACCOUNTING_DRIFT" not in gaps
    assert "ANALYZER_INCOMPLETE" in gaps
    assert coverage["source_accounting"]["state"] == "UNAVAILABLE"


def test_osv_coordinator_rejects_boolean_and_float_package_counts():
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [],
                    }
                ],
            }
        ]
    }
    required = {"requirements.txt": "a" * 64}
    lane = {"engine": "osv", "mode": "offline-pypi-snapshot"}
    account = _osv_source_accounting(report, required, lane["mode"])
    for forged_count in (True, 1.0):
        forged = json.loads(json.dumps(account))
        forged["sources"]["requirements.txt"]["package_count"] = forged_count
        coverage = {
            "schema": "factory.deep-coverage.v1",
            "sources": required,
            "complete": True,
            "errors": [],
            "mode": lane["mode"],
            "fallback": False,
            "report_sha256": digest(report),
            "source_accounting": forged,
        }
        assert "OSV_SOURCE_ACCOUNTING_DRIFT" in _coverage_source_gaps(
            report, coverage, lane, required
        )


@pytest.mark.parametrize("char", ['"', "*", "<", ">", "|"])
def test_audit_rejects_windows_invalid_source_path(char):
    from factoryline.deep_audit_io import relative_path

    with pytest.raises(RuntimeAuditError, match="E_PATH_ESCAPE"):
        relative_path(f"src/report{char}draft.py")


def test_execution_manifest_and_signed_authorization(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest
    from factoryline.deep_audit_attestation import verify_execution_authorization

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    assert load_execution_manifest(manifest, pin) == plan
    assert (
        verify_execution_authorization(
            plan, pin, authorization, trust, plan["trust_root_sha256"]
        )["candidate_sha256"]
        == plan["candidate_sha256"]
    )
    _, envelope_hash = verify_execution_authorization(
        plan,
        pin,
        authorization,
        trust,
        plan["trust_root_sha256"],
        return_envelope_sha256=True,
    )
    assert envelope_hash == digest(json.loads(authorization.read_text("utf-8")))
    with pytest.raises(RuntimeAuditError):
        verify_execution_authorization(
            plan, "0" * 64, authorization, trust, plan["trust_root_sha256"]
        )
    plan["lanes"][0]["argv"] = ["sh", "-c", "true"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TEMPLATE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def _v2_execution_plan(plan, inventory):
    from factoryline.deep_audit_contract import V2_NATIVE_ROLES

    plan["schema"] = "factory.deep-execution.v2"
    for lane in plan["lanes"]:
        lane["native_artifact_roles"] = sorted(V2_NATIVE_ROLES[lane["engine"]])
        if lane["engine"] != "syft":
            lane["rule_ids"] = ["fixture-detection"]
            lane["mutation_config_sha256"] = {"fixture-detection": "c" * 64}
    plan["obligations"] = [
        item for item in plan["obligations"] if item["engine"] != "syft"
    ]
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    for obligation in plan["obligations"]:
        for challenge in obligation["challenges"]:
            path = challenge["fixture_path"]
            challenge["fixture_sha256"] = sources[path]
            challenge["fixture_manifest"] = {path: sources[path]}
            challenge["fixture_manifest_sha256"] = digest({path: sources[path]})
    return plan


def test_execution_manifest_v2_binds_roles_and_fixture_manifest(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    pin = sha256_bytes(manifest.read_bytes())
    assert load_execution_manifest(manifest, pin) == plan

    plan["lanes"][0]["native_artifact_roles"] = ["sarif_report"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_NATIVE_ROLE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_v2_trivy_native_policy_identity_is_optional_and_strict(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    trivy = next(lane for lane in plan["lanes"] if lane["engine"] == "trivy")
    original_ruleset = trivy["ruleset_sha256"]
    policy = {"config_sha256": "e" * 64, "baseline_ignore_sha256": "f" * 64}
    trivy["native_policy"] = policy
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    assert (
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes())) == plan
    )
    assert trivy["ruleset_sha256"] == original_ruleset

    del trivy["native_policy"]
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    assert (
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes())) == plan
    )

    invalid_policies = [
        {"config_sha256": "e" * 64},
        {"config_sha256": "e" * 64, "baseline_ignore_sha256": "f" * 64, "extra": "x"},
        {"config_sha256": "bad", "baseline_ignore_sha256": "f" * 64},
        {"config_sha256": None, "baseline_ignore_sha256": "f" * 64},
    ]
    for invalid_policy in invalid_policies:
        candidate = deepcopy(plan)
        next(lane for lane in candidate["lanes"] if lane["engine"] == "trivy")[
            "native_policy"
        ] = invalid_policy
        manifest.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(RuntimeAuditError):
            load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))

    for schema, engine in (
        ("factory.deep-execution.v2", "codeql"),
        ("factory.deep-execution.v1", "trivy"),
    ):
        candidate = deepcopy(plan)
        candidate["schema"] = schema
        next(lane for lane in candidate["lanes"] if lane["engine"] == engine)[
            "native_policy"
        ] = policy
        manifest.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(RuntimeAuditError):
            load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def _signed_osv_v2_plan(tmp_path):
    from factoryline.deep_audit_contract import _osv_suppression_bytes

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    lane["mode"] = "offline-pypi-snapshot"
    lane["argv"] = [
        "/opt/factory/bin/audit-adapter",
        "osv",
        "--mode",
        "offline-pypi-snapshot",
    ]
    detector = lane["rule_ids"][0]
    aliases = sorted([detector, "CVE-2026-0001", "GHSA-abcd-1234-efgh"])
    lane["native_policy"] = {
        "database_path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        "database_sha256": lane["ruleset_sha256"],
        "baseline_config_sha256": sha256_bytes(b"\n"),
        "advisory_aliases": {detector: aliases},
    }
    lane["mutation_config_sha256"] = {
        detector: sha256_bytes(_osv_suppression_bytes(aliases))
    }
    target = {
        "package": "werkzeug",
        "ecosystem": "PyPI",
        "vulnerable_version": "0.16.1",
        "fixed_version": "0.16.2",
        "aliases": aliases,
    }
    next(item for item in plan["obligations"] if item["engine"] == "osv")[
        "osv_target"
    ] = target
    return manifest, plan, lane, target


def _write_and_load_signed_osv_plan(manifest, plan):
    from factoryline.deep_audit_contract import load_execution_manifest

    manifest.write_text(json.dumps(plan), encoding="utf-8")
    return load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def test_v2_signed_osv_policy_and_target_load_from_pinned_manifest(tmp_path):
    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, lane, target = _signed_osv_v2_plan(tmp_path)
    loaded = _write_and_load_signed_osv_plan(manifest, plan)
    loaded_lane = next(item for item in loaded["lanes"] if item["engine"] == "osv")
    loaded_obligation = next(
        item for item in loaded["obligations"] if item["engine"] == "osv"
    )
    assert loaded_lane["native_policy"] == lane["native_policy"]
    assert loaded_lane["mutation_config_sha256"] == lane["mutation_config_sha256"]
    assert loaded_obligation["osv_target"] == target
    assert _osv_suppression_bytes(target["aliases"]) == (
        b'[[IgnoredVulns]]\nid = "CVE-2026-0001"\n\n'
        b'[[IgnoredVulns]]\nid = "GHSA-abcd-1234-efgh"\n\n'
        b'[[IgnoredVulns]]\nid = "fixture-detection"\n\n'
    )


def test_v1_osv_manifest_remains_valid_without_native_policy_or_target(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, _, _ = execution_fixture(tmp_path)
    osv = next(item for item in plan["lanes"] if item["engine"] == "osv")
    obligation = next(item for item in plan["obligations"] if item["engine"] == "osv")
    assert "native_policy" not in osv
    assert "osv_target" not in obligation
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    loaded = load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))
    assert loaded == plan


def test_v2_osv_policy_rejects_native_policy_and_target_sabotage(tmp_path):
    from copy import deepcopy

    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, lane, target = _signed_osv_v2_plan(tmp_path)
    detector = lane["rule_ids"][0]

    mutations = []
    malformed_keys = deepcopy(plan)
    malformed_keys["lanes"][[item["engine"] for item in plan["lanes"]].index("osv")][
        "native_policy"
    ]["unexpected"] = True
    mutations.append(malformed_keys)

    for key, invalid in (
        ("database_path", "/src/osv-db/all.zip"),
        ("database_sha256", "0" * 64),
        ("baseline_config_sha256", "0" * 64),
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["native_policy"][key] = invalid
        mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"].pop("database_path")
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"].pop("baseline_config_sha256")
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["native_policy"]["advisory_aliases"] = {"another-rule": ["another-rule"]}
    mutations.append(candidate)

    candidate = deepcopy(plan)
    osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    osv["mode"] = "online-pypi"
    mutations.append(candidate)

    target_mutations = []
    target_missing = deepcopy(plan)
    next(item for item in target_missing["obligations"] if item["engine"] == "osv").pop(
        "osv_target"
    )
    target_mutations.append(target_missing)
    policy_missing = deepcopy(plan)
    next(item for item in policy_missing["lanes"] if item["engine"] == "osv").pop(
        "native_policy"
    )
    target_mutations.append(policy_missing)

    for field, invalid in (
        ("ecosystem", "npm"),
        ("package", "Werkzeug"),
        ("package", "a--b"),
        ("package", "../werkzeug"),
        ("vulnerable_version", "0.16.1\n--config"),
        ("fixed_version", "0.16.1"),
        ("aliases", sorted(["CVE-2026-0002", detector, "GHSA-abcd-1234-efgh"])),
    ):
        candidate = deepcopy(plan)
        osv_target = next(
            item for item in candidate["obligations"] if item["engine"] == "osv"
        )["osv_target"]
        osv_target[field] = invalid
        target_mutations.append(candidate)

    for candidate in mutations + target_mutations:
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)

    # Recomputed suppression hashes are required for every exact alias set.
    for aliases in (
        ["CVE-2026-0001", detector, "GHSA-abcd-1234-efgh"],
        ["CVE-2026-0001", "CVE-2026-0001", detector],
        ["CVE-2026-0001", "GHSA-abcd-1234-efgh"],
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["native_policy"]["advisory_aliases"][detector] = aliases
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)

    for mutation in (
        {},
        {"another-rule": "a" * 64},
        {detector: sha256_bytes(_osv_suppression_bytes(["CVE-2026-0002", detector]))},
        {detector: "not-a-digest"},
    ):
        candidate = deepcopy(plan)
        osv = next(item for item in candidate["lanes"] if item["engine"] == "osv")
        osv["mutation_config_sha256"] = mutation
        with pytest.raises(RuntimeAuditError):
            _write_and_load_signed_osv_plan(manifest, candidate)


def test_v2_osv_policy_rejects_cross_target_advisory_alias_overlap(tmp_path):
    from copy import deepcopy

    from factoryline.deep_audit_contract import _osv_suppression_bytes

    manifest, plan, _, _ = _signed_osv_v2_plan(tmp_path)
    candidate = deepcopy(plan)
    lane = next(item for item in candidate["lanes"] if item["engine"] == "osv")
    first, second = sorted(["fixture-detection", "osv-secondary"])
    aliases_one = sorted([first, "CVE-2026-0001"])
    aliases_two = sorted([second, "CVE-2026-0001"])
    lane["rule_ids"] = [first, second]
    lane["native_policy"]["advisory_aliases"] = {
        first: aliases_one,
        second: aliases_two,
    }
    lane["mutation_config_sha256"] = {
        first: sha256_bytes(_osv_suppression_bytes(aliases_one)),
        second: sha256_bytes(_osv_suppression_bytes(aliases_two)),
    }
    target_obligation = next(
        item for item in candidate["obligations"] if item["engine"] == "osv"
    )
    target_obligation["detector_rule_id"] = first
    target_obligation["osv_target"]["aliases"] = aliases_one
    with pytest.raises(RuntimeAuditError, match="E_OSV_TARGET"):
        _write_and_load_signed_osv_plan(manifest, candidate)


@pytest.mark.parametrize("malformed", [None, [], 7])
def test_v2_osv_manifest_rejects_malformed_obligation_without_crashing(
    tmp_path, malformed
):
    from copy import deepcopy

    manifest, plan, _, _ = _signed_osv_v2_plan(tmp_path)
    candidate = deepcopy(plan)
    index = next(
        index
        for index, item in enumerate(candidate["obligations"])
        if item["engine"] == "osv"
    )
    candidate["obligations"][index] = malformed
    with pytest.raises(RuntimeAuditError):
        _write_and_load_signed_osv_plan(manifest, candidate)


@pytest.mark.parametrize("policy_enabled", [False, True])
def test_v2_osv_signed_policy_metadata_never_verifies_native_challenge(
    policy_enabled,
):
    from factoryline.deep_audit_sarif import _challenge_execution_v2_valid

    lane = {"engine": "osv"}
    if policy_enabled:
        lane["native_policy"] = {"database_path": "pinned"}
    assert not _challenge_execution_v2_valid(
        {"status": "VERIFIED", "native_artifacts": {}},
        {"report": {"native_report": {}}},
        {},
        {},
        ("obligation-osv", "positive"),
        lane,
        {"source_accounting": {"state": "COMPLETE"}},
        "a" * 64,
    )


def test_v2_role_tables_match_native_helper_and_report_roles():
    from factoryline.deep_audit_contract import V2_NATIVE_ROLES
    from factoryline.deep_audit_sarif import _NATIVE_REPORT_ROLES
    from factoryline.runtime_audit_common import (
        NATIVE_ARTIFACT_ROLES,
        NATIVE_REPORT_ROLE,
    )

    assert V2_NATIVE_ROLES == NATIVE_ARTIFACT_ROLES
    assert _NATIVE_REPORT_ROLES == NATIVE_REPORT_ROLE


def _zap_target_fixture(inventory):
    source = inventory["files"][0]
    return {
        "schema": "factory.zap-target.v1",
        "image": "example.test/app@sha256:" + "a" * 64,
        "argv": ["/opt/app/bin/server", "--port", "8080"],
        "port": 8080,
        "readiness_path": "/health/ready",
        "routes": [
            {
                "id": "health",
                "method": "GET",
                "path": "/health/ready",
                "query": {"probe": "ready"},
                "source_bindings": {source["path"]: source["sha256"]},
            }
        ],
    }


def test_zap_target_contract_binds_sorted_routes_and_inventory_sources(tmp_path):
    from factoryline.deep_audit_contract import _validate_zap_target, _zap_target_url

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = _zap_target_fixture(inventory)
    route = target["routes"][0]

    assert _validate_zap_target(target, inventory) is None
    assert _zap_target_url(target) == "http://factory-target:8080/health/ready"
    assert _zap_target_url(target, route) == (
        "http://factory-target:8080/health/ready?probe=ready"
    )


def _python_trace_target(inventory):
    target = _zap_target_fixture(inventory)
    source = next(iter(target["routes"][0]["source_bindings"]))
    target["argv"] = ["/usr/bin/python3.11", f"/src/{source}", "--serve"]
    target["source_trace"] = {
        "schema": "factory.zap-source-trace.config.v1",
        "provider": "python-stdlib-http.v1",
        "max_events": 1000,
    }
    return target


def test_zap_source_trace_is_opt_in_and_accepts_bound_python_script(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_zap_target

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    legacy = _zap_target_fixture(inventory)
    assert _validate_zap_target(legacy, inventory) is None
    assert _validate_zap_target(_python_trace_target(inventory), inventory) is None

    duplicate = deepcopy(legacy)
    duplicate_route = deepcopy(duplicate["routes"][0])
    duplicate_route["id"] = "health_copy"
    duplicate_route["query"] = {"probe": "different"}
    duplicate["routes"].append(duplicate_route)
    duplicate["routes"].sort(key=lambda route: route["id"])
    assert _validate_zap_target(duplicate, inventory) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda config: config.update(extra=True),
        lambda config: config.update(schema="factory.zap-source-trace.config.v2"),
        lambda config: config.update(provider="python-framework.v1"),
        lambda config: config.update(max_events=0),
        lambda config: config.update(max_events=50_001),
        lambda config: config.update(max_events=True),
    ],
)
def test_zap_source_trace_rejects_invalid_exact_config(tmp_path, mutate):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_zap_target

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = deepcopy(_python_trace_target(inventory))
    mutate(target["source_trace"])

    with pytest.raises(RuntimeAuditError, match="E_ZAP_SOURCE_TRACE|E_FIELD"):
        _validate_zap_target(target, inventory)


@pytest.mark.parametrize(
    "argv",
    [
        ["/usr/bin/node", "/src/app.py"],
        ["python3", "/src/app.py"],
        ["/usr/bin/python2", "/src/app.py"],
        ["/usr/bin/python3", "-m", "app"],
        ["/usr/bin/python3", "/src/../app.py"],
        ["/usr/bin/python3", "/src/app.txt"],
    ],
)
def test_zap_source_trace_rejects_noncanonical_python_argv(tmp_path, argv):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_zap_target

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = deepcopy(_python_trace_target(inventory))
    target["argv"] = argv

    with pytest.raises(RuntimeAuditError, match="E_ZAP_SOURCE_TRACE|E_ZAP_TARGET"):
        _validate_zap_target(target, inventory)


def test_zap_source_trace_script_must_be_route_bound_and_routes_unique(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_zap_target

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = _python_trace_target(inventory)
    target["argv"][1] = "/src/clean.py"
    with pytest.raises(RuntimeAuditError, match="E_ZAP_SOURCE_TRACE"):
        _validate_zap_target(target, inventory)

    target = deepcopy(_python_trace_target(inventory))
    duplicate_route = deepcopy(target["routes"][0])
    duplicate_route["id"] = "health_copy"
    duplicate_route["query"] = {"probe": "different"}
    target["routes"].append(duplicate_route)
    target["routes"].sort(key=lambda route: route["id"])
    with pytest.raises(RuntimeAuditError, match="E_ZAP_SOURCE_TRACE"):
        _validate_zap_target(target, inventory)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda target: target.update(extra=True), "E_ZAP_TARGET"),
        (lambda target: target.update(image="app:latest"), "E_IMAGE_PIN"),
        (lambda target: target.update(argv=["app"]), "E_ZAP_TARGET"),
        (lambda target: target.update(port=65536), "E_FIELD"),
        (lambda target: target.update(readiness_path="/health/%2e%2e"), "E_ZAP_PATH"),
        (lambda target: target["routes"][0].update(method="POST"), "E_ZAP_ROUTE"),
        (lambda target: target["routes"][0].update(path="/a/../b"), "E_ZAP_PATH"),
        (lambda target: target["routes"][0].update(path="/a?x=1"), "E_ZAP_PATH"),
        (
            lambda target: target["routes"][0].update(query={"z": "1", "a": "2"}),
            "E_ZAP_ROUTE",
        ),
        (
            lambda target: target["routes"][0].update(
                source_bindings={"app.py": "0" * 64}
            ),
            "E_ZAP_TARGET_SOURCE",
        ),
    ],
)
def test_zap_target_rejects_invalid_descriptor_and_route_bindings(
    tmp_path, mutate, code
):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_zap_target

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = deepcopy(_zap_target_fixture(inventory))
    mutate(target)

    with pytest.raises(RuntimeAuditError, match=code):
        _validate_zap_target(target, inventory)


def test_zap_target_url_rejects_route_outside_signed_descriptor(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _zap_target_url

    _, _, _, _, _, _, inventory, _ = execution_fixture(tmp_path)
    target = _zap_target_fixture(inventory)
    route = deepcopy(target["routes"][0])
    route["path"] = "/different"

    with pytest.raises(RuntimeAuditError, match="E_ZAP_ROUTE"):
        _zap_target_url(target, route)


def test_native_target_is_optional_only_for_v2_zap_lane(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _execution_lane

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    lane = {
        "id": "zap",
        "engine": "zap",
        "family": "runtime",
        "image": "example.test/zap@sha256:" + "b" * 64,
        "argv": ["/opt/factory/bin/audit-adapter", "zap", "--mode", "full"],
        "report": "zap.json",
        "coverage": "zap-coverage.json",
        "challenge_report": "zap-challenges.json",
        "languages": ["python"],
        "mode": "full",
        "timeout_seconds": 10,
        "memory_mib": 256,
        "tool_version": "2.17.0",
        "ruleset_sha256": "c" * 64,
        "native_artifact_roles": ["zap_report"],
        "rule_ids": ["40012"],
        "mutation_config_sha256": {"40012": "d" * 64},
    }
    _execution_lane(lane, 2)
    lane["native_target"] = _zap_target_fixture(inventory)

    assert _execution_lane(lane, 2, inventory) is None
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_LANE"):
        _execution_lane(lane, 1)
    non_zap = deepcopy(lane)
    non_zap["engine"] = "runtime"
    non_zap["argv"] = ["/opt/factory/bin/audit-adapter", "runtime", "--mode", "full"]
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_LANE"):
        _execution_lane(non_zap, 2)


def test_signed_execution_manifest_binds_zap_target_and_route_sources(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_attestation import verify_execution_authorization
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, trust, plan, inventory, material = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    runtime_obligation = next(
        item for item in plan["obligations"] if item["engine"] == "runtime"
    )
    route_source = inventory["files"][0]
    lane = {
        "id": "zap",
        "engine": "zap",
        "family": "runtime",
        "image": "example.test/zap@sha256:" + "b" * 64,
        "argv": ["/opt/factory/bin/audit-adapter", "zap", "--mode", "full"],
        "report": "zap.json",
        "coverage": "zap-coverage.json",
        "challenge_report": "zap-challenges.json",
        "languages": ["python"],
        "mode": "full",
        "timeout_seconds": 10,
        "memory_mib": 256,
        "tool_version": "2.17.0",
        "ruleset_sha256": "c" * 64,
        "native_artifact_roles": ["zap_report"],
        "rule_ids": ["40012"],
        "mutation_config_sha256": {"40012": "d" * 64},
        "native_target": {
            "schema": "factory.zap-target.v1",
            "image": "example.test/app@sha256:" + "e" * 64,
            "argv": ["/opt/app/bin/server", "--port", "8080"],
            "port": 8080,
            "readiness_path": "/health/ready",
            "routes": [
                {
                    "id": "health",
                    "method": "GET",
                    "path": "/health/ready",
                    "query": {"probe": "ready"},
                    "source_bindings": {route_source["path"]: route_source["sha256"]},
                }
            ],
        },
    }
    plan["lanes"].append(lane)
    zap_obligation = deepcopy(runtime_obligation)
    zap_obligation.update(id="zap-route", engine="zap", detector_rule_id="40012")
    plan["obligations"].append(zap_obligation)

    manifest.write_text(json.dumps(plan), encoding="utf-8")
    pin = sha256_bytes(manifest.read_bytes())
    now = datetime.now(timezone.utc)
    payload = {
        "schema": "factory.deep-execution-authorization.v1",
        "manifest_sha256": pin,
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_content_sha256": digest(plan),
        "adapter_images": {item["id"]: item["image"] for item in plan["lanes"]},
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=50)).isoformat(),
        "authority": "none",
    }
    authorization = execution_sign(
        tmp_path / "control" / "authorization-zap.json",
        payload,
        material["coordinator"],
    )

    assert load_execution_manifest(manifest, pin, inventory) == plan
    assert (
        verify_execution_authorization(
            plan, pin, authorization, trust, plan["trust_root_sha256"]
        )["manifest_sha256"]
        == pin
    )

    lane["native_target"]["routes"][0]["path"] = "/changed"
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    changed_pin = sha256_bytes(manifest.read_bytes())
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_AUTHORIZATION"):
        verify_execution_authorization(
            plan,
            changed_pin,
            authorization,
            trust,
            plan["trust_root_sha256"],
        )


def test_semgrep_pattern_limited_is_supplemental_to_full_static_lane(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _execution_lanes

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    supplemental = deepcopy(plan["lanes"][0])
    supplemental.update(
        id="semgrep",
        engine="semgrep",
        mode="pattern-limited",
        argv=[
            "/opt/factory/bin/audit-adapter",
            "semgrep",
            "--mode",
            "pattern-limited",
        ],
    )
    plan["lanes"].append(supplemental)
    _v2_execution_plan(plan, inventory)

    accepted = _execution_lanes(plan["lanes"], 2)

    assert any(
        lane["engine"] == "semgrep" and lane["mode"] == "pattern-limited"
        for lane in accepted
    )
    assert any(
        lane["family"] == "static" and lane["mode"] == "interprocedural-full"
        for lane in accepted
    )


def test_semgrep_pattern_limited_cannot_replace_full_static_lane(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _execution_lanes

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    supplemental = deepcopy(plan["lanes"][0])
    supplemental.update(
        id="semgrep",
        engine="semgrep",
        mode="pattern-limited",
        argv=[
            "/opt/factory/bin/audit-adapter",
            "semgrep",
            "--mode",
            "pattern-limited",
        ],
    )
    plan["lanes"].append(supplemental)
    _v2_execution_plan(plan, inventory)
    plan["lanes"] = [lane for lane in plan["lanes"] if lane["engine"] != "codeql"]

    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_DEPTH"):
        _execution_lanes(plan["lanes"], 2)


def test_pattern_limited_mode_remains_rejected_for_other_static_engines():
    from factoryline.deep_audit_contract import _validate_lane_mode

    lane = {
        "engine": "codeql",
        "family": "static",
        "mode": "pattern-limited",
        "argv": [
            "/opt/factory/bin/audit-adapter",
            "codeql",
            "--mode",
            "pattern-limited",
        ],
    }
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_MODE"):
        _validate_lane_mode(lane)


def test_execution_manifest_v2_rejects_fixture_drift_and_syft_detector(tmp_path):
    from factoryline.deep_audit_contract import load_execution_manifest

    _, manifest, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    _v2_execution_plan(plan, inventory)
    challenge = plan["obligations"][0]["challenges"][0]
    challenge["fixture_manifest_sha256"] = "0" * 64
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_MANIFEST"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))

    _v2_execution_plan(plan, inventory)
    plan["obligations"].append(
        {
            "id": "syft-detector",
            "engine": "syft",
            "family": "dependencies",
            "detector_rule_id": "fixture-detection",
            "paths": ["app.py"],
            "requirements": ["app.py"],
            "remediation": "Inventory only.",
            "challenges": [],
        }
    )
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_ENGINE"):
        load_execution_manifest(manifest, sha256_bytes(manifest.read_bytes()))


def _zap_control_fixture(tmp_path):
    image = "example.test/app@sha256:" + "a" * 64
    native_target = {
        "schema": "factory.zap-target.v1",
        "image": image,
        "argv": ["/opt/app/bin/server"],
        "port": 8080,
        "readiness_path": "/ready",
        "routes": [
            {
                "id": "candidate",
                "method": "GET",
                "path": "/candidate",
                "query": {},
                "source_bindings": {"app.py": "b" * 64},
            }
        ],
    }
    lane = {
        "id": "zap",
        "engine": "zap",
        "family": "runtime",
        "rule_ids": ["40012"],
        "native_target": native_target,
    }
    challenges = []
    for kind, path, raw, route_id in (
        ("positive", "safe/positive.py", b"positive fixture", "safe-positive"),
        ("negative", "safe/negative.py", b"negative fixture", "safe-negative"),
        ("mutation", "safe/positive.py", b"positive fixture", "safe-positive"),
    ):
        source_sha = sha256_bytes(raw)
        if not (tmp_path / path).exists():
            (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / path).write_bytes(raw)
        route = {
            "id": route_id,
            "method": "GET",
            "path": "/probe",
            "query": {},
            "source_bindings": {path: source_sha},
        }
        target = {
            "schema": "factory.zap-target.v1",
            "image": image,
            "argv": ["/opt/app/bin/server", "--fixture", path],
            "port": 8080,
            "readiness_path": "/ready",
            "routes": [route],
        }
        manifest = {path: source_sha}
        challenges.append(
            {
                "kind": kind,
                "fixture_path": path,
                "fixture_sha256": source_sha,
                "expected_report_sha256": sha256_bytes(kind.encode()),
                "expected_exit_code": 0,
                "fixture_manifest": manifest,
                "fixture_manifest_sha256": digest(manifest),
                "zap_target": target,
                "zap_route_id": route_id,
            }
        )
    obligation = {
        "id": "zap-40012",
        "engine": "zap",
        "family": "runtime",
        "detector_rule_id": "40012",
        "paths": ["safe/positive.py"],
        "requirements": ["safe/positive.py"],
        "remediation": "Fix the detected issue.",
        "challenges": challenges,
    }
    return lane, obligation


def test_signed_zap_controls_bind_each_rule_route_and_fixture_tree(tmp_path):
    from factoryline.deep_audit_contract import (
        _validate_obligation,
        _zap_control_obligations,
        zap_signed_controls,
    )

    lane, obligation = _zap_control_fixture(tmp_path)
    _validate_obligation(obligation, [lane], 2)

    controls = _zap_control_obligations(lane, [obligation], tmp_path)

    assert controls == [obligation]
    assert controls[0]["challenges"][0]["zap_route_id"] == "safe-positive"
    assert zap_signed_controls(lane, [obligation], tmp_path) == {
        "40012": {
            "challenges": {item["kind"]: item for item in obligation["challenges"]}
        }
    }


def _mutate_zap_fixture_manifest(item):
    challenge = item["challenges"][1]
    challenge["fixture_manifest"]["safe/negative.py"] = "a" * 64
    challenge["fixture_sha256"] = "a" * 64
    item["challenges"][1]["fixture_manifest_sha256"] = digest(
        challenge["fixture_manifest"]
    )


def _mutate_zap_control_image(item):
    image = "example.test/other@sha256:" + "c" * 64
    item["challenges"][0]["zap_target"]["image"] = image
    item["challenges"][2]["zap_target"]["image"] = image


@pytest.mark.parametrize(
    "mutation,code",
    [
        (
            lambda item: item["challenges"][1].update(zap_route_id="missing"),
            "E_ZAP_CONTROL",
        ),
        (_mutate_zap_fixture_manifest, "E_ZAP_CONTROL"),
        (_mutate_zap_control_image, "E_ZAP_CONTROL"),
        (
            lambda item: item["challenges"][2].update(zap_route_id="other"),
            "E_HOLLOW_CHALLENGE",
        ),
        (
            lambda item: item["challenges"][2]["zap_target"]["argv"].append(
                "different"
            ),
            "E_HOLLOW_CHALLENGE",
        ),
    ],
)
def test_signed_zap_control_contract_rejects_unbound_route_or_mutation(
    tmp_path, mutation, code
):
    from copy import deepcopy
    from factoryline.deep_audit_contract import _validate_obligation

    lane, obligation = _zap_control_fixture(tmp_path)
    changed = deepcopy(obligation)
    mutation(changed)

    with pytest.raises(RuntimeAuditError, match=code):
        _validate_obligation(changed, [lane], 2)


def test_zap_control_selector_rejects_missing_duplicate_and_fixture_drift(tmp_path):
    from copy import deepcopy
    from factoryline.deep_audit_contract import zap_signed_controls

    lane, obligation = _zap_control_fixture(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ZAP_CONTROL"):
        zap_signed_controls(lane, [], tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ZAP_CONTROL"):
        zap_signed_controls(lane, [obligation, deepcopy(obligation)], tmp_path)

    (tmp_path / "safe" / "positive.py").write_bytes(b"drifted")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        zap_signed_controls(lane, [obligation], tmp_path)


def test_scan_rejects_authorization_changed_after_signature_verification(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit as module
    import factoryline.deep_audit_attestation as attestation

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    original = attestation.verify_execution_authorization

    def verify_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        document = json.loads(authorization.read_text("utf-8"))
        document["payload"] = (
            "A" if document["payload"][0] != "A" else "B"
        ) + document["payload"][1:]
        authorization.write_text(json.dumps(document), encoding="utf-8")
        return result

    monkeypatch.setattr(
        attestation, "verify_execution_authorization", verify_then_change
    )
    monkeypatch.setattr(module, "_docker_base", lambda: pytest.fail("must not launch"))
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_AUTHORIZATION_DRIFT"):
        module.scan_deep_audit(
            root,
            manifest,
            pin,
            authorization=authorization,
            trust_root=trust,
            trust_root_sha256=plan["trust_root_sha256"],
        )


@pytest.mark.parametrize("ignored", [False, True])
def test_operator_controls_do_not_change_candidate_inventory(tmp_path, ignored):
    import subprocess
    from factoryline.deep_audit_io import inventory_candidate

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    if ignored:
        (tmp_path / ".git/info/exclude").write_text(".factory/\n")
    original = inventory_candidate(tmp_path)
    controls = [
        ".factory/native-worker-config.json",
        ".factory/operator/manifest.json",
        ".factory/operator/authorization.json",
        ".factory/operator/trust.json",
    ]
    for revision in (1, 2):
        for name in controls:
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"revision": revision}))
        observed = inventory_candidate(tmp_path)
        assert observed["candidate_sha256"] == original["candidate_sha256"]
        assert observed["files"] == original["files"]
        assert observed["gaps"] == []
    hidden = tmp_path / ".factory/operator/source.py"
    hidden.write_text("print('must remain visible')\n")
    observed = inventory_candidate(tmp_path)
    if ignored:
        assert any(
            gap["code"] == "IGNORED_INPUT_SCOPE"
            and gap["path"] == ".factory/operator/source.py"
            for gap in observed["gaps"]
        )
    else:
        assert ".factory/operator/source.py" in {
            row["path"] for row in observed["files"]
        }
        assert observed["candidate_sha256"] != original["candidate_sha256"]


@pytest.mark.parametrize(
    "name",
    [
        ".factory/native-worker-config.json",
        ".factory/operator/manifest.json",
        ".factory/operator/authorization.json",
        ".factory/operator/trust.json",
    ],
)
def test_tracked_operator_control_collision_is_rejected(tmp_path, name):
    import subprocess
    from factoryline.deep_audit_io import inventory_candidate

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    subprocess.run(["git", "-C", str(tmp_path), "add", name], check=True)
    observed = inventory_candidate(tmp_path)
    assert any(
        gap["code"] == "E_RESERVED_SOURCE" and gap["path"] == name
        for gap in observed["gaps"]
    )


def test_inventory_accounts_ignored_deleted_unknown_and_dirty_inputs(tmp_path):
    from factoryline.deep_audit_io import inventory_candidate

    root, *rest = execution_fixture(tmp_path)
    original = inventory_candidate(root)
    (root / "app.py").write_text("print(2)\n", encoding="utf-8")
    assert inventory_candidate(root)["candidate_sha256"] != original["candidate_sha256"]
    (root / ".gitignore").write_text("hidden.py\n", encoding="utf-8")
    (root / "hidden.py").write_text("secret=1", encoding="utf-8")
    (root / "unknown.xyz").write_text("code", encoding="utf-8")
    (root / "app.py").unlink()
    result = inventory_candidate(root)
    assert result["state"] == "INCOMPLETE"
    assert "hidden.py" in result["ignored_paths"]
    assert {item["code"] for item in result["gaps"]} >= {
        "IGNORED_INPUT_SCOPE",
        "E_SOURCE_MISSING",
        "UNCLASSIFIED_INPUT",
    }


def test_snapshot_rejects_inside_source_and_detects_capture_drift(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit_io as module

    root, *rest = execution_fixture(tmp_path)
    inside = root / "snapshot"
    inside.mkdir()
    with pytest.raises(RuntimeAuditError, match="E_SNAPSHOT_PATH"):
        module.inventory_candidate(root, inside)
    inside.rmdir()
    original = module._source_bytes
    calls = 0

    def changing(root, name):
        nonlocal calls
        raw, mode = original(root, name)
        calls += 1
        if calls == 1:
            (root / name).write_bytes(b"print(3)\n")
        return raw, mode

    monkeypatch.setattr(module, "_source_bytes", changing)
    result = module.inventory_candidate(root)
    assert "SOURCE_DRIFT" in {gap["code"] for gap in result["gaps"]}


def test_execution_rejects_parser_downgrade_and_missing_mutations(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    initial = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert initial["state"] == "INCOMPLETE"
    assert initial["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    bundle["artifacts"]["coverage.json"]["fallback"] = True
    bundle["artifacts"]["challenges.json"]["observations"].pop()
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert set(result["gaps"]) >= {
        "ANALYSIS_MODE_DOWNGRADE",
        "CHALLENGE_COVERAGE_MISSING",
    }
    bundle["candidate_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_WORKER_BINDING"):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


@pytest.mark.parametrize("linked_temp", [False, True])
def test_scan_missing_engine_is_incomplete_with_durable_progress(
    tmp_path, monkeypatch, linked_temp
):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    if linked_temp:
        from contextlib import contextmanager

        target = tmp_path / "system-temp"
        target.mkdir()
        alias = tmp_path / "temp-alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlinks unavailable")
        original = module.tempfile.TemporaryDirectory

        @contextmanager
        def temporary_directory(*args, **kwargs):
            with original(*args, dir=alias, **kwargs) as directory:
                yield directory

        monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary_directory)

    def unavailable():
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "fixture unavailable")

    monkeypatch.setattr(module, "_docker_base", unavailable)
    events = []
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        emit=events.append,
    )
    assert result["state"] == "INCOMPLETE"
    assert not result["analysis_complete"]
    assert len(result["lanes"]) == 7
    assert events[0]["kind"] == "run_started"
    assert events[-1]["kind"] == "run_completed"
    assert all(lane["gaps"] == ["E_DOCKER_UNAVAILABLE"] for lane in result["lanes"])
    assert module.deep_run_status(root, result["run_id"])["state"] == "INCOMPLETE"
    assert len(module.execution_repairs(root, result["run_id"])["coverage_tasks"]) == 7


@pytest.mark.parametrize(
    "damage",
    [
        "missing_start",
        "missing_terminal",
        "duplicate",
        "unknown",
        "identity",
        "hash",
        "order",
        "duplicate_result",
        "final_details",
    ],
)
def test_native_action_coverage_reconciles_events_results_and_readback(
    tmp_path, monkeypatch, damage
):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import (
        digest,
        read_run_json,
        run_directory,
        write_run_json,
    )

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    monkeypatch.setattr(
        module,
        "_docker_base",
        lambda: (_ for _ in ()).throw(
            RuntimeAuditError("E_DOCKER_UNAVAILABLE", "fixture")
        ),
    )
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert result["action_coverage"]["state"] == "VERIFIED"
    status = module.deep_run_status(root, result["run_id"])
    assert status["action_coverage"] == result["action_coverage"]
    assert status["analysis_complete"] is False
    lineage_run, _, _ = module._lineage_run(root, result["run_id"])
    assert lineage_run["action_coverage"] == status["action_coverage"]

    directory = run_directory(root, result["run_id"])
    if damage == "missing_start":
        status, state, events = _observed_action_status(
            module,
            root,
            directory,
            result["run_id"],
            read_run_json,
            digest,
            write_run_json,
        )
        assert status["analysis_complete"] is True
        for invalid_plan in ({**plan, "lanes": []}, {**plan, "schema": "bad"}):
            assert (
                module._action_coverage(result, invalid_plan, [])["state"]
                == "INCOMPLETE"
            )
        duplicate_plan = {**plan, "lanes": [dict(row) for row in plan["lanes"]]}
        duplicate_plan["lanes"][1]["id"] = duplicate_plan["lanes"][0]["id"]
        assert (
            module._action_coverage(result, duplicate_plan, [])["state"] == "INCOMPLETE"
        )
        malformed = {**result, "lanes": [None]}
        assert module._action_coverage(malformed, plan, [])["state"] == "INCOMPLETE"
        state.pop("action_enrollment")
        assert (
            module._status_action_coverage(directory, state, events)["state"]
            == "INCOMPLETE"
        )

    events = [
        read_run_json(directory, f"event-{index:05d}.json")
        for index in range(1, status["sequence"] + 1)
    ]
    start = next(item for item in events if item["kind"] == "lane_started")
    terminal = next(item for item in events if item["kind"] == "lane_completed")
    _damage_action_test_events(damage, events, start, terminal)
    state = read_run_json(directory, "state.json")
    if damage == "duplicate_result":
        state["lanes"].append(dict(state["lanes"][0]))
    if damage == "final_details":
        events[-1]["details"] = None
    else:
        events[-1]["details"]["analysis_complete"] = True
    _rechain_action_test_events(directory, events, state, digest, write_run_json)
    damaged = module.deep_run_status(root, result["run_id"])
    assert damaged["action_coverage"]["state"] == "INCOMPLETE"
    if damage != "final_details":
        assert any(
            damaged["action_coverage"][key]
            for key in (
                "missing_starts",
                "missing_terminals",
                "duplicates",
                "unexpected",
                "mismatches",
            )
        )
    assert damaged["analysis_complete"] is False


def test_scan_never_executes_with_different_candidate(tmp_path, monkeypatch):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    (root / "app.py").write_text("print(4)\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "_docker_base",
        lambda: pytest.fail("execution before candidate binding"),
    )
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert "CANDIDATE_DRIFT" in {gap["code"] for gap in result["gaps"]}
    assert result["lanes"] == []


def test_container_contract_removes_privileges_and_host_execution(tmp_path):
    from factoryline.deep_audit import _container_argv

    _, _, _, _, _, plan, _, _ = execution_fixture(tmp_path)
    command = _container_argv(
        ["docker"], plan["lanes"][0], tmp_path, "test", "0" * 32, "1" * 64
    )
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pull=never",
    ):
        assert flag in command
    assert not any(
        "docker.sock" in value or value == "--privileged" for value in command
    )


@pytest.mark.parametrize("engine", ["codeql", "syft", "osv"])
def test_execution_native_errors_cannot_pass(tmp_path, engine):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    if engine == "codeql":
        assert result["state"] == "INCOMPLETE"
        assert result["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    elif engine == "osv":
        assert result["state"] == "INCOMPLETE"
        assert "OSV_NATIVE_ARTIFACTS_UNVERIFIED" in result["gaps"]
    else:
        assert result["state"] == "OBSERVED"
    assert result["obligations"] == [lane["engine"]]
    report = bundle["artifacts"]["report.json"]
    if engine == "codeql":
        report["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": "partial"}}
        ]
    else:
        report["errors"] = ["partial"]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    with pytest.raises(RuntimeAuditError):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


def _execute_lane_replay_case(
    tmp_path,
    monkeypatch,
    *,
    replay_action=None,
    cleanup_succeeds=True,
    engine="codeql",
    gaps=None,
    worker_replay_claim=False,
):
    import factoryline.deep_audit as module
    import factoryline.deep_audit_sarif as sarif

    from factoryline.runtime_audit_common import canonical_bytes

    root, _, pin, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    run_id = "b" * 32
    bundle = execution_bundle(lane, inventory, run_id)
    if worker_replay_claim:
        bundle["artifacts"][lane["coverage"]]["native_replay"] = {
            "state": "VERIFIED",
            "authority": "worker-claim",
        }
    raw = canonical_bytes(bundle)
    events, replay_calls = [], []
    directory = root / ".factory" / "test-run"
    directory.mkdir(parents=True)
    state = {
        "run_id": run_id,
        "manifest_sha256": pin,
        "active_lane": lane["id"],
    }

    monkeypatch.setattr(module, "_docker_base", lambda: ["docker"])
    monkeypatch.setattr(module, "_docker_preflight", lambda base, item: None)
    monkeypatch.setattr(module, "_container_argv", lambda *args: ["docker", "run"])
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)

    def cleanup(base, name):
        events.append("cleanup")
        return cleanup_succeeds

    monkeypatch.setattr(module, "_container_cleanup", cleanup)

    def run(argv, cwd, timeout, scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(raw)
        return {
            "exit_code": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "cancelled": False,
        }

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    monkeypatch.setattr(
        sarif,
        "normalize_execution_bundle",
        lambda *args: {
            "lane_id": lane["id"],
            "state": "INCOMPLETE" if gaps else "OBSERVED",
            "findings": [],
            "gaps": list(gaps or []),
        },
    )

    def replay(*args, **kwargs):
        events.append("replay")
        replay_calls.append((args, kwargs))
        if isinstance(replay_action, BaseException):
            raise replay_action
        if callable(replay_action):
            return replay_action(*args, **kwargs)
        return replay_action or {"state": "VERIFIED", "authority": "host"}

    monkeypatch.setattr(module, "_replay_codeql_lane", replay, raising=False)
    result = module._execute_lane(
        root,
        directory,
        state,
        root,
        lane,
        inventory,
        {"obligations": plan["obligations"]},
        lambda event: None,
    )
    return result, events, replay_calls, bundle


def test_execute_lane_replays_codeql_only_after_container_cleanup(
    tmp_path, monkeypatch
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED", "UNRELATED_GAP"],
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert result["gaps"] == ["UNRELATED_GAP"]
    assert result["state"] == "INCOMPLETE"
    assert result["codeql_replay"] == {"state": "VERIFIED", "authority": "host"}


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeAuditError("E_CODEQL_REPLAY_UNAVAILABLE", "missing"),
        RuntimeAuditError("E_CODEQL_REPLAY_MALFORMED", "invalid output"),
        RuntimeAuditError("E_ADAPTER_TIMEOUT", "expired"),
        RuntimeAuditError("E_CODEQL_REPLAY_CLEANUP", "uncertain cleanup"),
        {"state": "MALFORMED"},
    ],
)
def test_execute_lane_replay_failure_keeps_codeql_incomplete(
    tmp_path, monkeypatch, failure
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        replay_action=failure,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert result["state"] == "INCOMPLETE"
    assert "CODEQL_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["codeql_replay"]["state"] == "INCOMPLETE"
    assert result["codeql_replay"]["diagnostic_code"]


@pytest.mark.parametrize(
    "failure_kind,exit_code,cleanup_succeeds",
    [("native_exit", 7, True), ("docker_cleanup", 0, False)],
)
def test_replay_failure_retains_safe_execution_receipt(
    tmp_path, monkeypatch, failure_kind, exit_code, cleanup_succeeds
):
    import threading
    import time

    import factoryline.deep_audit as module

    lane = {
        "id": "codeql-replay-test",
        "engine": "codeql",
        "coverage": "coverage.json",
        "report": "report.sarif",
        "timeout_seconds": 30,
        "image": "sha256:" + "a" * 64,
    }
    inventory = {"candidate_sha256": "b" * 64}
    bundle = {"artifacts": {"coverage.json": {}, "report.sarif": {}}}
    snapshot = tmp_path / "source snapshot private path"
    snapshot.mkdir()
    runtime = tmp_path / "trusted runtime"
    runtime.mkdir()
    stdout = b"private replay stdout"
    stderr = b"private replay stderr"
    facts = {
        "exit_code": exit_code,
        "timed_out": False,
        "timeout_seconds": 30,
        "duration_ms": 12,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "cancelled": False,
    }
    monkeypatch.setattr(module, "_docker_preflight", lambda *args: None)
    monkeypatch.setattr(
        module, "_codeql_replay_runtime", lambda scratch: (runtime, "c" * 64)
    )
    monkeypatch.setattr(
        module, "_codeql_replay_argv", lambda *args: ["docker", "run", str(snapshot)]
    )
    monkeypatch.setattr(
        module,
        "_container_cleanup",
        lambda *args: cleanup_succeeds,
    )

    def run(argv, cwd, timeout, scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(stdout)
        return facts

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError) as caught:
        module._replay_codeql_lane(
            ["docker"],
            lane,
            snapshot,
            bundle,
            inventory,
            "d" * 32,
            threading.Event(),
        )

    error = caught.value
    evidence = error.replay_evidence
    assert evidence["image"] == lane["image"]
    assert evidence["runtime_sha256"] == "c" * 64
    assert len(evidence["command_sha256"]) == 64
    assert evidence["execution"] == facts
    assert evidence["cleanup_confirmed"] is cleanup_succeeds
    rendered = repr(evidence)
    assert "private replay stdout" not in rendered
    assert "private replay stderr" not in rendered
    assert str(snapshot) not in rendered
    assert str(runtime) not in rendered

    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    result = {
        "gaps": ["CODEQL_NATIVE_REPLAY_REQUIRED"],
        "state": "INCOMPLETE",
    }
    monkeypatch.setattr(
        module,
        "_replay_codeql_lane",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    directory = tmp_path / "run"
    directory.mkdir()
    module._codeql_replay_result(
        result,
        ["docker"],
        lane,
        snapshot,
        bundle,
        inventory,
        "d" * 32,
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": lane["id"]}, lambda event: None),
    )
    assert result["state"] == "INCOMPLETE"
    assert "CODEQL_NATIVE_REPLAY_REQUIRED" in result["gaps"]
    assert "CODEQL_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["codeql_replay"]["evidence"] == evidence
    rendered_result = repr(result)
    assert "private replay stdout" not in rendered_result
    assert "private replay stderr" not in rendered_result
    assert str(snapshot) not in rendered_result
    assert str(runtime) not in rendered_result


def test_execute_lane_cleanup_failure_skips_codeql_replay(tmp_path, monkeypatch):
    replayed = []
    with pytest.raises(RuntimeAuditError, match="E_CONTAINER_CLEANUP"):
        _execute_lane_replay_case(
            tmp_path,
            monkeypatch,
            cleanup_succeeds=False,
            gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
            replay_action=lambda *args: replayed.append(args),
        )
    assert replayed == []


def test_execute_lane_ignores_worker_replay_claim_and_requires_host_replay(
    tmp_path, monkeypatch
):
    result, events, calls, bundle = _execute_lane_replay_case(
        tmp_path,
        monkeypatch,
        gaps=["CODEQL_NATIVE_REPLAY_REQUIRED"],
        worker_replay_claim=True,
    )
    assert bundle["artifacts"]["coverage.json"]["native_replay"]["authority"] == (
        "worker-claim"
    )
    assert events == ["cleanup", "replay"]
    assert len(calls) == 1
    assert "CODEQL_NATIVE_REPLAY_REQUIRED" not in result["gaps"]
    assert result["codeql_replay"]["authority"] == "host"


@pytest.mark.parametrize("engine,gaps", [("syft", ["OTHER_GAP"]), ("codeql", [])])
def test_execute_lane_skips_replay_when_not_required(
    tmp_path, monkeypatch, engine, gaps
):
    result, events, calls, _ = _execute_lane_replay_case(
        tmp_path, monkeypatch, engine=engine, gaps=gaps
    )
    assert events == ["cleanup"]
    assert calls == []
    assert result["gaps"] == gaps


@pytest.mark.parametrize("change", ["golden", "fixture", "exit", "boolean"])
def test_execution_challenges_require_bound_evidence(tmp_path, change):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    challenge = bundle["artifacts"]["challenges.json"]["observations"][0]
    if change == "golden":
        challenge["report"] = {"result": "made up"}
        challenge["observation_sha256"] = digest(challenge["report"])
    elif change == "fixture":
        challenge["fixture_sha256"] = "0" * 64
    elif change == "exit":
        challenge["exit_code"] = True
    else:
        challenge.pop("report")
        challenge["passed"] = True
    try:
        result = normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )
    except RuntimeAuditError:
        assert change in {"boolean", "golden"}
    else:
        assert result["state"] == "INCOMPLETE"
        assert "CHALLENGE_FAILED" in result["gaps"]


def synthetic_execution(tmp_path, monkeypatch):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import write_run_json
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    args = execution_fixture(tmp_path)
    root, manifest, pin, authorization, trust, plan, _, _ = args

    def execute(root, directory, state, snapshot, lane, inventory, plan, emit):
        bundle = execution_bundle(lane, inventory, state["run_id"])
        result = normalize_execution_bundle(
            bundle, lane, inventory, state["run_id"], plan["obligations"]
        )
        write_run_json(directory, f"bundle-{lane['id']}.json", bundle)
        result.update(
            bundle_sha256=digest(bundle),
            execution={
                "exit_code": 0,
                "cleanup_confirmed": True,
                "timed_out": False,
                "output_limit_exceeded": False,
                "launch_error": False,
                "cancelled": False,
            },
        )
        return result

    monkeypatch.setattr(module, "_execute_lane", execute)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert not result["analysis_complete"]
    assert any(
        "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" in lane["gaps"]
        for lane in result["lanes"]
    )
    assert (
        result["state"] == "INCOMPLETE"
    )  # Synthetic observations alone never approve.
    return args, result


def review_documents(tmp_path, args, evidence, findings=None, gaps=None):
    from factoryline.deep_audit_io import read_run_json, run_directory

    root, _, pin, _, _, plan, inventory, material = args
    # Sign persisted execution evidence, excluding advisory CLI attachments.
    evidence = read_run_json(run_directory(root, evidence["run_id"]), "evidence.json")
    now = datetime.now(timezone.utc)
    common = {
        "run_id": evidence["run_id"],
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_sha256": pin,
        "evidence_sha256": digest(evidence),
        "read_set_sha256": digest(inventory["files"]),
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=40)).isoformat(),
        "authority": "none",
        "provider": "fixture-only",
        "model": "synthetic",
        "invocation_id": "fixture",
        "specialty": "security",
        "prompt_sha256": "1" * 64,
        "response_sha256": "2" * 64,
    }
    review = {
        **common,
        "schema": "factory.deep-specialty-review.v1",
        "decision": "ACCEPT",
        "findings": findings or [],
        "coverage_gaps": gaps or [],
    }
    invocation = {
        **common,
        "schema": "factory.deep-review-invocation.v1",
        "read_only": True,
        "review_payload_sha256": digest(review),
    }
    return (
        execution_sign(tmp_path / "review.json", review, material["reviewer"]),
        execution_sign(
            tmp_path / "invocation.json", invocation, material["coordinator"]
        ),
    )


@pytest.mark.parametrize("disposition", ["accept", "high", "gap"])
def test_specialty_review_reconciles_its_own_findings(
    tmp_path, monkeypatch, disposition
):
    from factoryline.deep_audit_attestation import verify_execution_review

    args, result = synthetic_execution(tmp_path, monkeypatch)
    findings = (
        [
            {
                "id": "review-1",
                "severity": "high",
                "path": "app.py",
                "evidence": "fixture",
                "remediation": "repair",
            }
        ]
        if disposition == "high"
        else []
    )
    gaps = ["missing runtime observation"] if disposition == "gap" else []
    attestation, invocation = review_documents(tmp_path, args, result, findings, gaps)
    with pytest.raises(RuntimeAuditError, match="E_REVIEW_NORMALIZATION"):
        verify_execution_review(
            args[0],
            result["run_id"],
            attestation,
            invocation,
            args[4],
            args[5]["trust_root_sha256"],
        )
    # Isolate disposition/signature reconciliation after proving the real native
    # gate rejects incomplete secrets coverage. This is not an integration pass.
    monkeypatch.setattr(
        "factoryline.deep_audit_attestation._review_native_lanes", lambda *args: None
    )
    reviewed = verify_execution_review(
        args[0],
        result["run_id"],
        attestation,
        invocation,
        args[4],
        args[5]["trust_root_sha256"],
    )
    assert (
        reviewed["state"]
        == {"accept": "INCOMPLETE", "high": "BLOCKED", "gap": "INCOMPLETE"}[disposition]
    )
    assert reviewed["specialty_ai_review"] == "COORDINATOR_ATTESTED"
    assert reviewed["authority"] == "none" and not reviewed["release_approval"]


def test_progress_detects_earlier_event_tamper(tmp_path, monkeypatch):
    from factoryline.deep_audit import deep_run_status
    from factoryline.deep_audit_io import read_run_json, write_run_json, run_directory

    args, result = synthetic_execution(tmp_path, monkeypatch)
    directory = run_directory(args[0], result["run_id"])
    event = read_run_json(directory, "event-00001.json")
    event["details"] = {"changed": True}
    write_run_json(directory, "event-00001.json", event)
    with pytest.raises(RuntimeAuditError, match="E_EVENT_INTEGRITY"):
        deep_run_status(args[0], result["run_id"])


def test_execution_role_trust_cannot_be_self_declared(tmp_path):
    from factoryline.deep_audit_attestation import _execution_keys

    _, _, _, _, trust, plan, _, _ = execution_fixture(tmp_path)
    value = json.loads(trust.read_text())
    value["keys"][1]["roles"] = ["implementer"]
    trust.write_text(json.dumps(value))
    with pytest.raises(RuntimeAuditError, match="E_REVIEW_TRUST"):
        _execution_keys(plan, trust)


@pytest.mark.parametrize("engine", ["syft", "osv"])
def test_native_dependency_reports_cannot_omit_declared_input(tmp_path, engine):
    from factoryline.deep_audit_sarif import (
        _osv_source_accounting,
        normalize_execution_bundle,
    )

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    if engine == "syft":
        report["artifacts"][0]["locations"].pop()
    else:
        report["results"].pop()
        lane["mode"] = "offline-pypi-snapshot"
        coverage = bundle["artifacts"]["coverage.json"]
        coverage["mode"] = lane["mode"]
        coverage["complete"] = False
        coverage["errors"] = ["NATIVE_SOURCE_ACCOUNTING_REQUIRED"]
        coverage["report_sha256"] = digest(report)
        expected_accounting = _osv_source_accounting(
            report,
            {item["path"]: item["sha256"] for item in inventory["files"]},
            lane["mode"],
        )
        coverage["source_accounting"] = expected_accounting
    if engine == "syft":
        bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
        with pytest.raises(RuntimeAuditError, match="E_DEPENDENCY_COVERAGE"):
            normalize_execution_bundle(
                bundle, lane, inventory, "0" * 32, plan["obligations"]
            )
    else:
        observed = normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )
        assert observed["state"] == "INCOMPLETE"
        assert "OSV_SOURCE_ACCOUNTING_INCOMPLETE" in observed["gaps"]
        assert observed["covered_paths"] == expected_accounting["measured_paths"]
        assert observed["covered_paths"] != sorted(
            item["path"] for item in inventory["files"]
        )
        assert observed["source_accounting"] == expected_accounting


def test_osv_normalization_exposes_empty_packages_despite_forged_complete_flag(
    tmp_path,
):
    from factoryline.deep_audit_sarif import (
        _osv_source_accounting,
        normalize_execution_bundle,
    )

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    lane["mode"] = "offline-pypi-snapshot"
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    report["results"][0]["packages"] = []
    required = {item["path"]: item["sha256"] for item in inventory["files"]}
    account = _osv_source_accounting(report, required, lane["mode"])
    coverage = bundle["artifacts"]["coverage.json"]
    coverage.update(
        {
            "complete": True,
            "errors": [],
            "mode": lane["mode"],
            "report_sha256": digest(report),
            "source_accounting": account,
        }
    )

    observed = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert observed["state"] == "INCOMPLETE"
    assert "OSV_SOURCE_ACCOUNTING_INCOMPLETE" in observed["gaps"]
    assert observed["source_accounting"] == account
    assert observed["covered_paths"] == account["measured_paths"]
    assert observed["findings"] == []


def test_execution_osv_preserves_package_advisory_and_fixed_version(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    package = report["results"][0]["packages"][0]
    package["vulnerabilities"] = [
        {
            "id": "OSV-TEST-1",
            "affected": [
                {
                    "package": {"name": "fixture", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.4.6"}]}],
                }
            ],
        }
    ]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    finding = result["findings"][0]
    assert finding["dependency"] == {
        "package": {"name": "fixture", "version": "1.0", "ecosystem": "PyPI"},
        "advisory_id": "OSV-TEST-1",
        "fixed_versions": ["2.4.6"],
        "aliases": [],
    }
    assert "2.4.6" in finding["remediation"]
    assert result["authority"] == "none"


@pytest.mark.parametrize(
    "bad_affected", ["not-a-list", [{"ranges": [{"events": [{"fixed": 42}]}]}]]
)
def test_execution_osv_rejects_malformed_fixed_version_evidence(tmp_path, bad_affected):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "osv")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    package = report["results"][0]["packages"][0]
    package["vulnerabilities"] = [{"id": "OSV-TEST-1", "affected": bad_affected}]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)

    with pytest.raises(RuntimeAuditError):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


@pytest.mark.parametrize("engine", ["runtime", "atheris"])
@pytest.mark.parametrize("failure", ["generic", "zero", "coverage"])
def test_runtime_evidence_requires_engine_execution_and_source_depth(
    tmp_path, engine, failure
):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    if failure == "generic":
        report["schema"] = "factory.runtime-observations.v1"
    elif failure == "zero":
        report["metrics"] = {key: 0 for key in report["metrics"]}
    else:
        report["source_coverage"]["app.py"]["lines_covered"] = 0
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    with pytest.raises(RuntimeAuditError):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


@pytest.mark.parametrize(
    "engine, expected_metrics",
    [
        ("runtime", {"tests": 1}),
        ("atheris", {"executions": 1000, "coverage_edges": 10, "corpus_size": 5}),
    ],
)
def test_runtime_and_fuzz_metrics_survive_normalized_projection(
    tmp_path, engine, expected_metrics
):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == engine)
    bundle = execution_bundle(lane, inventory, "0" * 32)

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    assert result["state"] == ("INCOMPLETE" if engine == "atheris" else "OBSERVED")
    if engine == "atheris":
        assert "FUZZ_NATIVE_CORPUS_UNVERIFIED" in result["gaps"]
    assert result["metrics"] == expected_metrics
    assert result["authority"] == "none"


def test_execution_sarif_trace_details_survive_projection(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "codeql")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    report = bundle["artifacts"]["report.json"]
    report["runs"][0]["results"] = execution_native(lane, inventory, detected=True)[
        "runs"
    ][0]["results"]
    report["runs"][0]["results"][0]["codeFlows"] = [
        {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {
                                        "startLine": 2,
                                        "endLine": 2,
                                        "startColumn": 4,
                                        "endColumn": 9,
                                    },
                                }
                            },
                            "kinds": ["source"],
                        }
                    ]
                }
            ]
        }
    ]
    bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    source_hash = next(
        item["sha256"] for item in inventory["files"] if item["path"] == "app.py"
    )

    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )

    assert result["findings"][0]["flows"] == [
        [
            {
                "path": "app.py",
                "source_sha256": source_hash,
                "start_line": 2,
                "end_line": 2,
                "start_column": 4,
                "end_column": 9,
                "kinds": ["source"],
            }
        ]
    ]
    assert result["findings"][0]["trace_depth"] == 1
    assert len(result["findings"][0]["trace_sha256"]) == 64
    assert result["findings"][0]["native_identity_state"] == "NOT_MEASURED"
    assert result["authority"] == "none"


def test_signed_golden_cannot_replace_positive_detection_semantics(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = plan["lanes"][0]
    bundle = execution_bundle(lane, inventory, "0" * 32)
    challenge = bundle["artifacts"]["challenges.json"]["observations"][0]
    challenge["report"]["native_report"]["runs"][0]["results"] = []
    challenge["observation_sha256"] = digest(challenge["report"])
    plan["obligations"][0]["challenges"][0]["expected_report_sha256"] = challenge[
        "observation_sha256"
    ]
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_SEMANTICS"):
        normalize_execution_bundle(
            bundle, lane, inventory, "0" * 32, plan["obligations"]
        )


def test_specialty_review_stages_do_not_hide_complexity():
    import ast
    import inspect
    import textwrap
    import factoryline.deep_audit_attestation as module

    stages = (
        "verify_execution_review",
        "_review_candidate",
        "_review_native_lanes",
        "_review_dispositions",
        "_review_finding",
        "_review_provenance",
        "_execution_document",
        "_execution_freshness",
        "_execution_signer",
    )
    for name in stages:
        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(module, name))))
        complexity = 1
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        assert complexity <= 10, (name, complexity)


@pytest.mark.parametrize("surface", ["primary", "challenge"])
def test_execution_sarif_defaults_preserve_original_hashes(tmp_path, surface):
    from copy import deepcopy
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "codeql")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    if surface == "primary":
        report = execution_native(lane, inventory, detected=True)
        bundle["artifacts"]["report.json"] = report
    else:
        observation = bundle["artifacts"]["challenges.json"]["observations"][0]
        report = observation["report"]["native_report"]
    run = report["runs"][0]
    run["results"][0].pop("level")
    run["tool"]["driver"]["rules"] = [
        {"id": "fixture-detection", "defaultConfiguration": {"level": "error"}}
    ]
    if surface == "primary":
        bundle["artifacts"]["coverage.json"]["report_sha256"] = digest(report)
    else:
        observation["observation_sha256"] = digest(observation["report"])
        obligation = next(
            item for item in plan["obligations"] if item["engine"] == "codeql"
        )
        obligation["challenges"][0]["expected_report_sha256"] = digest(
            observation["report"]
        )
    original = deepcopy(bundle)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["gaps"] == ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    assert bundle == original


def test_secrets_sidecar_cannot_claim_native_scan_coverage(tmp_path):
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "gitleaks")
    bundle = execution_bundle(lane, inventory, "0" * 32)
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["state"] == "INCOMPLETE"
    assert "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" in result["gaps"]


def test_failure_playback_is_paged_and_tamper_checked(tmp_path, monkeypatch):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import read_run_json, run_directory, write_run_json

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)

    def unavailable():
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "private diagnostic")

    monkeypatch.setattr(module, "_docker_base", unavailable)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    page = module.playback_deep_run(root, result["run_id"], limit=3)
    assert len(page["events"]) == 3 and page["has_more"]
    events = module.playback_deep_run(root, result["run_id"], limit=500)["events"]
    failures = [
        event["details"] for event in events if event["kind"] == "failure_recorded"
    ]
    assert len(failures) == 7
    assert all(item["code"] == "E_DOCKER_UNAVAILABLE" for item in failures)
    assert all(
        item["candidate_sha256"] == plan["candidate_sha256"] for item in failures
    )
    assert "private diagnostic" not in json.dumps(events)
    directory = run_directory(root, result["run_id"])
    event = read_run_json(directory, "event-00001.json")
    event["details"] = {}
    write_run_json(directory, "event-00001.json", event)
    with pytest.raises(RuntimeAuditError, match="E_EVENT_INTEGRITY"):
        module.playback_deep_run(root, result["run_id"])


def test_pause_stops_between_lanes_and_resume_revalidates(tmp_path, monkeypatch):
    import factoryline.deep_audit as module

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)
    calls = []

    def lane(*args):
        state, definition = args[2], args[4]
        calls.append(definition["id"])
        request = module.pause_deep_run(root, state["run_id"])
        assert request["state"] == "PAUSE_REQUESTED"
        return {
            "lane_id": definition["id"],
            "state": "INCOMPLETE",
            "findings": [],
            "gaps": ["WORKER_FAILED"],
            "execution": {"cancelled": True},
        }

    monkeypatch.setattr(module, "_execute_lane", lane)
    result = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
    )
    assert result["state"] == "PAUSED" and not result["analysis_complete"]
    assert result["action_coverage"]["state"] == "INCOMPLETE"
    assert result["lanes"][0]["family"] == plan["lanes"][0]["family"]
    assert result["lanes"][0]["engine"] == plan["lanes"][0]["engine"]
    assert len(calls) == 1
    assert (
        module.playback_deep_run(root, result["run_id"])["events"][-1]["kind"]
        == "run_paused"
    )
    assert module.pause_deep_run(root, result["run_id"])["state"] == "ALREADY_STOPPED"
    retried = module.scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        resume=result["run_id"],
    )
    assert retried["parent_run"] == result["run_id"]
    assert retried["run_id"] != result["run_id"] and len(calls) == 2
    with pytest.raises(RuntimeAuditError, match="E_RESUME_DRIFT"):
        from factoryline.deep_audit_io import read_run_json, run_directory

        module._check_resume(
            root,
            result["run_id"],
            "0" * 64,
            plan,
            None,
            read_run_json,
            run_directory,
        )


@pytest.mark.parametrize("after,limit", [(-1, 100), (True, 100), (0, 0), (0, 501)])
def test_playback_rejects_invalid_bounds(tmp_path, after, limit):
    import factoryline.deep_audit as module
    from factoryline.deep_audit_io import run_directory

    run_id = "a" * 32
    state = {"schema": "factory.deep-run.v1", "run_id": run_id, "state": "PAUSED"}
    module._event(
        run_directory(tmp_path, run_id, create=True), state, "run_started", {}
    )
    with pytest.raises(RuntimeAuditError, match="E_PLAYBACK_RANGE"):
        module.playback_deep_run(tmp_path, run_id, after=after, limit=limit)


def test_osv_fixed_versions_do_not_cross_package_boundaries():
    from factoryline.deep_audit_sarif import _osv_fixed_versions

    identity = {"name": "target", "ecosystem": "PyPI"}
    vulnerability = {
        "affected": [
            {
                "package": {"name": "other", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "9"}]}],
            },
            {"ranges": [{"events": [{"fixed": "8"}]}]},
            {"package": identity, "ranges": [{"events": [{"fixed": "2"}]}]},
        ]
    }
    assert _osv_fixed_versions(vulnerability, identity) == ["2"]


def _local_runner_lane():
    # Supplied unit-test digests do not establish upstream signature verification.
    binding = {
        "kind": "local-native",
        "platform": {"os": "windows", "architecture": "x86_64"},
        "profile_sha256": "a" * 64,
        "tool_manifest": {
            "path": str(Path.cwd().anchor + "operator-tools/manifest.json"),
            "sha256": "b" * 64,
        },
        "ruleset_sha256": "c" * 64,
        "provenance": {
            "release_url": "https://github.com/opengrep/opengrep/releases/download/v1.15.0/opengrep_windows_x86.exe",
            "artifact_sha256": "d" * 64,
            "verification_receipt_sha256": "e" * 64,
        },
        "grants": {
            "read": ["captured-source", "rules", "tool-bundle"],
            "write": ["scratch", "output"],
            "network": False,
            "candidate_execution": False,
        },
    }
    from factoryline.deep_audit_contract import V2_NATIVE_ROLES

    return {
        "id": "local-opengrep",
        "engine": "semgrep",
        "family": "static",
        "runner_binding": binding,
        "argv": ["factory-native-profile", "a" * 64],
        "report": "report.json",
        "coverage": "coverage.json",
        "challenge_report": "challenge.json",
        "languages": ["typescript"],
        "mode": "pattern-limited",
        "timeout_seconds": 10,
        "memory_mib": 128,
        "tool_version": "1.15.0",
        "ruleset_sha256": "c" * 64,
        "native_artifact_roles": sorted(V2_NATIVE_ROLES["semgrep"]),
        "rule_ids": ["test-rule"],
        "mutation_config_sha256": {"test-rule": "f" * 64},
    }


def test_local_manifest_loader_receives_resolved_candidate_root(tmp_path, monkeypatch):
    from factoryline import deep_audit, deep_audit_contract

    class LoaderReached(Exception):
        pass

    def loader(*args, candidate_root=None, **kwargs):
        assert candidate_root == tmp_path.resolve()
        raise LoaderReached

    monkeypatch.setattr(deep_audit_contract, "load_execution_manifest", loader)
    with pytest.raises(LoaderReached):
        deep_audit.scan_deep_audit(
            tmp_path,
            tmp_path / "manifest.json",
            "a" * 64,
            authorization=tmp_path / "auth.json",
            trust_root=tmp_path / "trust.json",
            trust_root_sha256="b" * 64,
        )


@pytest.mark.parametrize("failure", ["walk", "early-file", "manifest"])
def test_operator_tool_manifest_rejects_incomplete_or_changed_tree(
    tmp_path, monkeypatch, failure
):
    from factoryline import deep_audit_attestation as attestation

    lane, root = _local_tool_bundle(tmp_path)
    if failure == "walk":

        def unreadable(*args, onerror=None, **kwargs):
            assert onerror is not None
            onerror(PermissionError("inaccessible subtree"))
            return iter(())

        monkeypatch.setattr(attestation._deep_audit_io.os, "walk", unreadable)
    else:
        original = attestation._local_tool_file

        def change_earlier(bundle, row):
            result = original(bundle, row)
            if row["role"] == "provenance":
                target = "executable" if failure == "early-file" else "manifest.json"
                (bundle / target).write_bytes(b"changed after prior verification")
            return result

        monkeypatch.setattr(attestation, "_local_tool_file", change_earlier)
    with pytest.raises(
        RuntimeAuditError, match="tool inventory unreadable|tool bundle changed"
    ):
        attestation.verify_local_tool_manifest(
            lane["runner_binding"], candidate_root=tmp_path / "candidate"
        )


def _local_tool_bundle(tmp_path):
    lane = _local_runner_lane()
    binding = lane["runner_binding"]
    root = tmp_path / "operator"
    root.mkdir()
    rows = []
    for role in ("executable", "resource", "profile", "rules", "provenance"):
        raw = (role + "\n").encode()
        (root / role).write_bytes(raw)
        rows.append(
            {"path": role, "sha256": sha256_bytes(raw), "bytes": len(raw), "role": role}
        )
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps({"schema": "factory.local-tool-manifest.v1", "files": rows})
    )
    binding["tool_manifest"] = {
        "path": str(manifest),
        "sha256": sha256_bytes(manifest.read_bytes()),
    }
    binding["profile_sha256"] = rows[2]["sha256"]
    binding["ruleset_sha256"] = lane["ruleset_sha256"] = rows[3]["sha256"]
    binding["provenance"]["artifact_sha256"] = rows[0]["sha256"]
    binding["provenance"]["verification_receipt_sha256"] = rows[4]["sha256"]
    return lane, root


@pytest.mark.parametrize(
    "damage",
    [None, "drift", "extra", "missing", "inside", "no-root", "profile", "manifest"],
)
def test_operator_tool_manifest_binds_actual_complete_bundle(tmp_path, damage):
    from factoryline.deep_audit_attestation import verify_local_tool_manifest

    lane, root = _local_tool_bundle(tmp_path)
    binding = lane["runner_binding"]
    candidate = tmp_path / "candidate"
    mutations = {
        "drift": lambda: (root / "resource").write_bytes(b"changed"),
        "extra": lambda: (root / "extra.dll").write_bytes(b"unbound"),
        "missing": lambda: (root / "resource").unlink(),
        "profile": lambda: binding.update(profile_sha256="a" * 64),
        "manifest": lambda: binding["tool_manifest"].update(sha256="a" * 64),
    }
    if damage in mutations:
        mutations[damage]()
    if damage == "inside":
        candidate = root.parent
    if damage == "no-root":
        candidate = None
    if damage is None:
        assert (
            len(verify_local_tool_manifest(binding, candidate_root=candidate)["files"])
            == 5
        )
    else:
        with pytest.raises(RuntimeAuditError):
            verify_local_tool_manifest(binding, candidate_root=candidate)


@pytest.mark.parametrize("link", ["file", "directory", "ancestor"])
def test_operator_tool_manifest_rejects_linked_bundle(tmp_path, link):
    from factoryline.deep_audit_attestation import verify_local_tool_manifest

    lane, root = _local_tool_bundle(tmp_path)
    try:
        if link == "ancestor":
            alias = tmp_path / "alias"
            alias.symlink_to(root, target_is_directory=True)
            lane["runner_binding"]["tool_manifest"]["path"] = str(
                alias / "manifest.json"
            )
        elif link == "directory":
            (root / "linked").symlink_to(tmp_path, target_is_directory=True)
        else:
            (root / "linked").symlink_to(root / "resource")
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(RuntimeAuditError):
        verify_local_tool_manifest(
            lane["runner_binding"], candidate_root=tmp_path / "candidate"
        )


@pytest.mark.parametrize(
    "damage", [None, "missing", "extra", "stale", "image-substitution"]
)
def test_local_runner_requires_exact_signed_provider_map(tmp_path, damage):
    from factoryline.deep_audit_attestation import verify_execution_authorization

    _, _, _, _, trust, plan, _, material = execution_fixture(tmp_path)
    lane = _local_runner_lane()
    plan["lanes"].append(lane)
    pin = "f" * 64
    now = datetime.now(timezone.utc)
    payload = {
        "schema": "factory.deep-execution-authorization.v1",
        "manifest_sha256": pin,
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_content_sha256": digest(plan),
        "adapter_images": {
            item["id"]: item["image"] for item in plan["lanes"] if "image" in item
        },
        "local_runner_bindings": {lane["id"]: digest(lane["runner_binding"])},
        "issued_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "authority": "none",
    }
    if damage == "missing":
        payload.pop("local_runner_bindings")
    elif damage == "extra":
        payload["local_runner_bindings"]["unapproved"] = "a" * 64
    elif damage == "stale":
        payload["local_runner_bindings"][lane["id"]] = "a" * 64
    elif damage == "image-substitution":
        payload["adapter_images"][lane["id"]] = digest(lane["runner_binding"])
    authorization = execution_sign(
        tmp_path / "local-auth.json", payload, material["coordinator"]
    )
    if damage is None:
        assert (
            verify_execution_authorization(
                plan, pin, authorization, trust, plan["trust_root_sha256"]
            )
            == payload
        )
    else:
        with pytest.raises(RuntimeAuditError, match="E_ADAPTER_AUTHORIZATION"):
            verify_execution_authorization(
                plan, pin, authorization, trust, plan["trust_root_sha256"]
            )


@pytest.mark.parametrize("field", ["os", "architecture"])
@pytest.mark.parametrize("value", [[], {}, None, False, True, 0, 1, 1.5])
def test_local_runner_platform_types_fail_with_contract_error(field, value):
    from factoryline.deep_audit_contract import _execution_lane

    lane = _local_runner_lane()
    lane["runner_binding"]["platform"][field] = value
    with pytest.raises(RuntimeAuditError):
        _execution_lane(lane, 2)


def test_local_runner_closed_v2_lane_and_legacy_rejection():
    from factoryline.deep_audit_contract import _execution_lane

    lane = _local_runner_lane()
    _execution_lane(lane, 2)
    with pytest.raises(RuntimeAuditError):
        _execution_lane(lane, 1)


@pytest.mark.parametrize(
    "damage",
    [
        "image",
        "neither",
        "extra",
        "manifest",
        "rules",
        "profile",
        "platform",
        "grant-extra",
        "grant-missing",
        "network",
        "bool-alias",
        "provenance-missing",
        "provenance-extra",
        "release-platform",
        "receipt",
        "runtime",
    ],
)
def test_local_runner_rejects_ambiguous_or_unbound_contract(damage):
    from factoryline.deep_audit_contract import _execution_lane

    lane = _local_runner_lane()
    binding = lane["runner_binding"]
    mutations = {
        "image": (lane, "image", "sha256:" + "a" * 64),
        "neither": (lane, "runner_binding", None),
        "extra": (binding, "self_verified", True),
        "manifest": (binding["tool_manifest"], "sha256", "bad"),
        "rules": (binding, "ruleset_sha256", "a" * 64),
        "profile": (binding, "profile_sha256", "b" * 64),
        "platform": (binding["platform"], "os", "macos"),
        "grant-extra": (binding["grants"], "execute", True),
        "grant-missing": (binding["grants"], "write", None),
        "network": (binding["grants"], "network", True),
        "bool-alias": (binding["grants"], "network", 0),
        "provenance-missing": (binding["provenance"], "artifact_sha256", None),
        "provenance-extra": (binding["provenance"], "verified", True),
        "release-platform": (binding["platform"], "os", "linux"),
        "receipt": (binding["provenance"], "verification_receipt_sha256", "bad"),
        "runtime": (lane, "engine", "runtime"),
    }
    target, key, value = mutations[damage]
    if value is None:
        target.pop(key)
    else:
        target[key] = value
    with pytest.raises(RuntimeAuditError):
        _execution_lane(lane, 2)


@pytest.mark.parametrize(
    "field,output",
    [
        ("image_sha256", "image_binding_sha256"),
        ("runner_binding_sha256", "runner_binding_sha256"),
    ],
)
def test_native_challenge_provider_identity_preserves_container_and_local(
    field, output
):
    from factoryline.runtime_audit_common import _execution_provider_identity

    assert _execution_provider_identity({field: "a" * 64}) == {output: "a" * 64}


@pytest.mark.parametrize(
    "bindings",
    [
        {},
        {"image_sha256": "a" * 64, "runner_binding_sha256": "b" * 64},
        {"runner_binding_sha256": "bad"},
    ],
)
def test_native_challenge_rejects_missing_dual_or_invalid_identity(bindings):
    from factoryline.runtime_audit_common import _execution_provider_identity

    with pytest.raises(RuntimeAuditError):
        _execution_provider_identity(bindings)


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("version", [1, 2])
def test_native_challenge_facts_use_actual_provider_binding(local, version):
    from factoryline.runtime_audit_common import (
        _native_execution,
        _native_execution_v2,
        _validate_execution_bindings,
        canonical_bytes,
    )

    facts = {
        "exit_code": 0,
        "timed_out": False,
        "timeout_seconds": 10,
        "duration_ms": 1,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": "a" * 64,
        "stderr_sha256": "b" * 64,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    data = {
        "fixture_manifest": {"a.ts": "c" * 64},
        "fixture_sha": "c" * 64,
        "fixture_manifest_sha": "c" * 64,
        "baseline_sha": "d" * 64,
        "effective_sha": "d" * 64,
    }
    identity = "runner_binding_sha256" if local else "image_sha256"
    bindings = {
        "candidate_sha256": "e" * 64,
        "challenge_source_sha256": sha256_bytes(
            canonical_bytes(data["fixture_manifest"])
        ),
        "profile_sha256": "f" * 64,
        identity: "a" * 64,
        "tool_version": "1.15.0",
        "version_probe_sha256": sha256_bytes(canonical_bytes(facts)),
        "version_probe_facts": facts,
    }
    _validate_execution_bindings({}, data, bindings)
    args = (
        "PASS",
        facts,
        0,
        "b" * 64,
        data,
        bindings,
        "c" * 64,
        True,
        True,
        "positive",
        "rule",
        10,
    )
    result = (
        _native_execution(*args) if version == 1 else _native_execution_v2(*args, [])
    )
    key = "runner_binding_sha256" if local else "image_binding_sha256"
    assert result[key] == "a" * 64
    assert ("image_binding_sha256" if local else "runner_binding_sha256") not in result
    seal = result.pop("execution_sha256")
    assert seal == sha256_bytes(canonical_bytes(result))
    bindings["image_sha256" if local else "runner_binding_sha256"] = "b" * 64
    with pytest.raises(RuntimeAuditError):
        _validate_execution_bindings({}, data, bindings)


def test_coordinator_cheap_preflight_keeps_signed_identity_without_inventory(
    tmp_path, monkeypatch
):
    import factoryline.cli_deep_audit as module
    from factoryline import assembly_process, deep_audit_io

    # This is a preflight unit control, not a native process-identity probe.
    monkeypatch.setattr(
        assembly_process, "_process_creation_identity", lambda pid: "unit-owner"
    )
    root, request, owner, context, _ = _coordinator_signed_fixture(tmp_path)
    full = module._coordinator_preflight(root, request["payload"])

    def forbidden(*args, **kwargs):
        raise AssertionError("cheap preflight must not inventory the candidate")

    monkeypatch.setattr(deep_audit_io, "inventory_candidate", forbidden)
    cheap = module._coordinator_preflight(root, request["payload"], inventory=False)
    # Patching a loaded module intentionally changes the runtime identity itself.
    expected = module._coordinator_identity_view(full)
    assert {k: v for k, v in cheap.items() if k != "runtime_sha256"} == {
        k: v for k, v in expected.items() if k != "runtime_sha256"
    }
    assert "inventory_sha256" in full and "inventory_sha256" not in cheap
    context["store"].release(owner)


def test_coordinator_owner_check_reuses_runtime_identity(tmp_path, monkeypatch):
    import time
    import factoryline.cli_deep_audit as module
    from factoryline import assembly_process

    # Keep identity stable on unsupported native hosts without skipping this check.
    monkeypatch.setattr(
        assembly_process, "_process_creation_identity", lambda pid: "unit-owner"
    )
    root, request, owner, context, _ = _coordinator_signed_fixture(tmp_path)

    def forbidden():
        raise AssertionError("per-request owner checks must not rehash the runtime")

    monkeypatch.setattr(module, "_coordinator_runtime_identity", forbidden)
    for _ in range(5):
        module._coordinator_check_owner(root, request, owner, context)
    with pytest.raises(ValueError):
        module._coordinator_check_owner(
            root, request, dict(owner, runtime_sha256="0" * 64), context
        )
    context["expires_at"] = time.monotonic() - 1
    with pytest.raises(ValueError):
        module._coordinator_check_owner(root, request, owner, context)
    context["store"].release(owner)


class _RenewStore:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def acquire(self, owner, ttl, now):
        from factoryline.agentic_control import AgenticControlError

        self.calls.append((owner, ttl))
        if self.error:
            raise AgenticControlError(self.error, "synthetic contention")
        return {"expires_monotonic": now + ttl}


class _Thread:
    def __init__(self, alive):
        self.alive = alive

    def is_alive(self):
        return self.alive


@pytest.mark.parametrize(
    "remaining,active,activity,stop,renewed",
    [
        (100, True, False, False, True),
        (100, False, True, False, True),
        (100, False, False, False, False),
        (200, True, False, False, False),
        (-1, True, True, False, False),
        (100, True, True, True, False),
    ],
)
def test_coordinator_renews_live_lease_only_while_active(
    remaining, active, activity, stop, renewed
):
    import time
    import factoryline.cli_deep_audit as module

    store = _RenewStore()
    expires = time.monotonic() + remaining
    context = dict(
        store=store,
        owner={"pid": 1},
        ttl=300,
        stop=stop,
        expires_at=expires,
        job={"thread": _Thread(active)},
    )
    module._coordinator_renew(context, activity=activity)
    assert bool(store.calls) is renewed
    if renewed:
        assert context["expires_at"] > expires + 100
    else:
        assert context["expires_at"] == expires


def test_coordinator_renewal_contention_retries_and_direct_api_never_renews():
    import time
    import factoryline.cli_deep_audit as module

    expires = time.monotonic() + 10
    store = _RenewStore("E_COORDINATOR_BUSY")
    context = dict(store=store, owner={}, ttl=300, stop=False, expires_at=expires)
    context["job"] = {"thread": _Thread(True)}
    module._coordinator_renew(context)
    assert store.calls and context["expires_at"] == expires
    direct = dict(store=_RenewStore(), stop=False, expires_at=expires, job=None)
    module._coordinator_renew(direct, activity=True)
    assert direct["store"].calls == []


def test_coordinator_defers_pre_ack_worker_during_metadata_contention(
    tmp_path, monkeypatch
):
    import threading
    import time

    import factoryline.cli_deep_audit as module
    from factoryline import assembly_process
    from factoryline.agentic_control import CoordinatorRequestStore
    from factoryline.graph_authorization import _authorization_lock

    monkeypatch.setattr(
        assembly_process, "_process_creation_identity", lambda pid: f"fixture:{pid}"
    )
    root = tmp_path.resolve()
    store = CoordinatorRequestStore(root)
    nonce = "1" * 32
    owner = module._coordinator_owner(root, nonce, "2" * 64)
    lease = store.acquire(owner, 60, time.monotonic())
    request = dict(session_nonce=nonce, workspace=str(root))
    context = dict(
        stop=False,
        expires_at=lease["expires_monotonic"],
        store=CoordinatorRequestStore(root),
    )
    job = dict(cancel=threading.Event(), acknowledged=False, directory=root)

    with _authorization_lock(store.path):
        assert module._coordinator_heartbeat(root, request, owner, context, job)
        assert not job["cancel"].is_set()
        assert not job["acknowledged"]

    assert module._coordinator_heartbeat(root, request, owner, context, job)
    context["expires_at"] = time.monotonic() - 1
    assert not module._coordinator_heartbeat(root, request, owner, context, job)
    assert job["cancel"].is_set()
    assert not job["acknowledged"]


@pytest.mark.parametrize(
    "memory_mib, ram_mib", [(1024, 768), (2048, 1536), (4096, 3072), (8192, 7168)]
)
def test_codeql_ram_follows_signed_lane_memory(memory_mib, ram_mib):
    import sys

    from factoryline.deep_audit_contract import _codeql_ram_mib, _native_argv

    lane = {"memory_mib": memory_mib}
    assert _codeql_ram_mib(lane) == ram_mib
    command = {"argv": [sys.executable, "--ram={ram_mib}"], "accepted_exit_codes": [0]}
    assert _native_argv([command], {}, lane)[0]["argv"][1] == f"--ram={ram_mib}"
    with pytest.raises(RuntimeAuditError, match="lane memory binding required"):
        _native_argv([command], {})


@pytest.mark.parametrize("codeql", [False, True])
def test_native_ram_binding_preserves_literal_report_path(codeql):
    from factoryline.deep_audit_contract import _native_argv

    report = "/out/report-{ram_mib}.json"
    import sys

    argv = [sys.executable, "--output={report}"]
    expected = [sys.executable, f"--output={report}"]
    lane = {"engine": "semgrep"}
    if codeql:
        argv.append("--ram={ram_mib}")
        expected.append("--ram=1536")
        lane = {"engine": "codeql", "memory_mib": 2048}
    result = _native_argv(
        [{"argv": argv, "accepted_exit_codes": [0]}], {"report": report}, lane
    )
    assert result[0]["argv"] == expected


@pytest.mark.parametrize(
    "language",
    ["python", "javascript", "ruby", "actions", "java", "csharp", "go", "rust"],
)
def test_shipped_codeql_profiles_bind_ram_to_lane(language):
    profile = json.loads(
        (
            Path(__file__).parents[1]
            / f"deploy/deep-adapters/profiles/codeql-{language}-full.json"
        ).read_text()
    )
    analyze = profile["commands"][1]["argv"]
    assert analyze[1:3] == ["database", "analyze"]
    assert [a for a in analyze if a.startswith("--ram=")] == ["--ram={ram_mib}"]

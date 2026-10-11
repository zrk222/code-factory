from copy import deepcopy
import json

import pytest

from factoryline.deep_audit_io import digest, relative_path, strict_json
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    sha256_bytes,
)

ANALYZER = {"id": "scanner", "driver": "Example", "version": "1"}


OSV_CHALLENGE_ALIASES = [
    "CVE-2026-0001",
    "GHSA-abcd-1234-efgh",
    "fixture-detection",
]


def _osv_challenge_advisory(*, aliases=None, details="native advisory metadata"):
    return {
        "id": "CVE-2026-0001",
        "aliases": list(aliases if aliases is not None else OSV_CHALLENGE_ALIASES[1:]),
        "details": details,
        "modified": "2026-01-02T03:04:05Z",
    }


def _osv_challenge_package(name, version, vulnerabilities=()):
    return {
        "package": {"name": name, "version": version, "ecosystem": "PyPI"},
        "vulnerabilities": list(vulnerabilities),
    }


def _osv_challenge_fixture(kind):
    from factoryline.deep_audit_sarif import _osv_challenge_rows

    target = {
        "package": "werkzeug",
        "ecosystem": "PyPI",
        "vulnerable_version": "0.16.1",
        "fixed_version": "0.16.2",
        "aliases": list(OSV_CHALLENGE_ALIASES),
    }
    target_version = (
        target["fixed_version"] if kind == "negative" else target["vulnerable_version"]
    )
    anchor = "requirements.txt"
    other_advisory = _osv_challenge_advisory(details="unrelated package row")
    target_advisories = [_osv_challenge_advisory()] if kind == "positive" else []
    report = {
        "results": [
            {
                "source": {"path": anchor},
                "packages": [
                    _osv_challenge_package(
                        target["package"], target_version, target_advisories
                    ),
                    _osv_challenge_package(
                        "other-library", "1.2.3", [deepcopy(other_advisory)]
                    ),
                    _osv_challenge_package(
                        "other-library", "1.2.3", [deepcopy(other_advisory)]
                    ),
                ],
            },
            {
                "source": {"path": "other.txt"},
                "packages": [
                    _osv_challenge_package(
                        target["package"],
                        target["vulnerable_version"],
                        [_osv_challenge_advisory(details="same advisory, other path")],
                    )
                ],
            },
        ]
    }
    sources = {anchor: "a" * 64, "other.txt": "b" * 64}
    obligation = {
        "osv_target": target,
        "challenges": [
            {"kind": control_kind, "fixture_path": anchor}
            for control_kind in ("positive", "negative", "mutation")
        ],
    }
    lane = {
        "engine": "osv",
        "id": "osv-challenge-test",
        "mode": "offline-pypi-snapshot",
    }
    result = _osv_challenge_rows(report, lane, sources, obligation, kind)
    return result, report, lane, sources, obligation


def _osv_retained_evidence_fixture():
    from factoryline.deep_audit_io import _codeql_native_blob, _osv_suppression_bytes
    from factoryline.deep_audit_sarif import (
        _osv_challenge_rows,
        _osv_source_accounting,
    )

    rule_id = "OSV-CVE-2026-0001"
    aliases = list(OSV_CHALLENGE_ALIASES)
    manifest = {"requirements.txt": "a" * 64, "other.txt": "b" * 64}
    database = {
        "path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        "sha256": "c" * 64,
        "bytes": 123,
    }
    database_raw = canonical_bytes(database)
    suppression = _osv_suppression_bytes(aliases)
    lane = {
        "engine": "osv",
        "id": "osv-retained-test",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
        "ruleset_sha256": sha256_bytes(b"\n"),
        "rule_ids": [rule_id],
        "mutation_config_sha256": {rule_id: sha256_bytes(suppression)},
        "native_artifact_roles": ["advisory_db_identity", "osv_json_report"],
        "native_policy": {
            "database_path": database["path"],
            "database_sha256": database["sha256"],
            "baseline_config_sha256": sha256_bytes(b"\n"),
            "advisory_aliases": {rule_id: aliases},
        },
    }
    target = {
        "package": "werkzeug",
        "ecosystem": "PyPI",
        "vulnerable_version": "0.16.1",
        "fixed_version": "0.16.2",
        "aliases": aliases,
    }
    controls = [
        {
            "kind": kind,
            "fixture_path": "requirements.txt",
            "fixture_sha256": manifest["requirements.txt"],
            "fixture_manifest": manifest,
            "fixture_manifest_sha256": digest(manifest),
        }
        for kind in ("positive", "negative", "mutation")
    ]
    obligation = {
        "id": "osv-werkzeug-target",
        "engine": "osv",
        "family": "dependencies",
        "detector_rule_id": rule_id,
        "paths": sorted(manifest),
        "osv_target": target,
        "challenges": controls,
    }
    observations = []
    primary_report = None
    for control in controls:
        _, report, _, _, _ = _osv_challenge_fixture(control["kind"])
        summary = _osv_challenge_rows(
            report, lane, manifest, obligation, control["kind"]
        )
        raw = canonical_bytes(report)
        config = suppression if control["kind"] == "mutation" else b"\n"
        db_blob = _codeql_native_blob(database_raw)
        raw_blob = _codeql_native_blob(raw)
        config_blob = _codeql_native_blob(config)
        artifacts = [
            {
                "kind": "advisory_db_identity",
                "sha256": sha256_bytes(database_raw),
                "bytes": len(database_raw),
            },
            {
                "kind": "osv_json_report",
                "sha256": sha256_bytes(raw),
                "bytes": len(raw),
            },
        ]
        wrapper = {
            "schema": "factory.deep-challenge-observation.v1",
            "engine": "osv",
            "fixture_sha256": manifest["requirements.txt"],
            "detector_rule_id": rule_id,
            "detector_enabled": control["kind"] != "mutation",
            "native_report": report,
        }
        observation = {
            "obligation_id": obligation["id"],
            "kind": control["kind"],
            "report": wrapper,
            "observation_sha256": digest(wrapper),
            "osv_control_evidence": summary,
            "execution": {
                "status": "VERIFIED",
                "baseline_config_sha256": lane["native_policy"][
                    "baseline_config_sha256"
                ],
                "challenge_source_sha256": digest(manifest),
                "raw_report_sha256": sha256_bytes(raw),
                "effective_config_sha256": sha256_bytes(config),
                "native_artifacts": artifacts,
            },
            "osv_native_evidence": {
                "schema": "factory.osv-retained-challenge.v1",
                "source_root": "/src/control",
                "source_manifest": manifest,
                "source_manifest_sha256": digest(manifest),
                "raw_report": raw_blob,
                "effective_config": config_blob,
                "database_identity": db_blob,
            },
        }
        observations.append(observation)
        if control["kind"] == "positive":
            primary_report = report

    coverage = {
        "report_sha256": digest(primary_report),
        "native_report_sha256": digest(primary_report),
        "source_accounting": _osv_source_accounting(
            primary_report, manifest, lane["mode"]
        ),
        "osv_native_evidence": {
            "schema": "factory.osv-native-evidence.v1",
            "source_bindings": manifest,
            "primary": {
                "raw_report": _codeql_native_blob(canonical_bytes(primary_report)),
                "database_identity": _codeql_native_blob(database_raw),
            },
        },
    }
    challenges = {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": [],
    }
    return coverage, lane, manifest, primary_report, challenges, [obligation]


def test_osv_challenge_rows_anchor_positive_and_preserve_unrelated_duplicates():
    result, report, _, _, _ = _osv_challenge_fixture("positive")
    assert result["schema"] == "factory.osv-challenge-rows.v1"
    assert result["report_sha256"] == digest(report)
    assert len(result["target_rows"]) == 1
    target = result["target_rows"][0]
    assert target["path"] == "requirements.txt"
    assert target["package"] == {
        "name": "werkzeug",
        "version": "0.16.1",
        "ecosystem": "PyPI",
    }
    assert set([target["advisory_id"], *target["aliases"]]) == set(
        OSV_CHALLENGE_ALIASES
    )
    assert target["aliases"] == sorted(target["aliases"])
    assert target["advisory_sha256"] == digest(
        report["results"][0]["packages"][0]["vulnerabilities"][0]
    )
    unrelated = result["unrelated_rows"]
    assert len(unrelated) == 3
    duplicate_rows = [
        row for row in unrelated if row["package"]["name"] == "other-library"
    ]
    assert len(duplicate_rows) == 2
    assert duplicate_rows[0] == duplicate_rows[1]
    assert duplicate_rows[0]["advisory_sha256"] == digest(
        report["results"][0]["packages"][1]["vulnerabilities"][0]
    )
    assert any(row["path"] == "other.txt" for row in unrelated)
    assert len(result["inventory"]) == 4


@pytest.mark.parametrize(
    "kind,expected_version", [("negative", "0.16.2"), ("mutation", "0.16.1")]
)
def test_osv_challenge_safe_controls_anchor_exact_package_and_keep_same_advisory_unrelated(
    kind, expected_version
):
    result, _, _, _, _ = _osv_challenge_fixture(kind)
    assert result["target_rows"] == []
    assert any(
        row["path"] == "requirements.txt"
        and row["name"] == "werkzeug"
        and row["version"] == expected_version
        for row in result["inventory"]
    )
    assert len(result["unrelated_rows"]) == 3
    assert all(
        row["advisory_id"] == "CVE-2026-0001" for row in result["unrelated_rows"]
    )


@pytest.mark.parametrize(
    "aliases,expected_error",
    [
        (["GHSA-abcd-1234-efgh"], "positive advisory family differs"),
        (["GHSA-abcd-1234-efgh", "OSV-UNSIGNED"], "unsigned advisory alias"),
    ],
)
def test_osv_positive_rejects_incomplete_or_unsigned_alias_families(
    aliases, expected_error
):
    from factoryline.deep_audit_sarif import _osv_challenge_rows

    _, report, lane, sources, obligation = _osv_challenge_fixture("positive")
    report["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"] = aliases
    with pytest.raises(RuntimeAuditError, match=expected_error):
        _osv_challenge_rows(report, lane, sources, obligation, "positive")


@pytest.mark.parametrize("damage", ["wrong_package", "wrong_version", "wrong_path"])
def test_osv_challenges_require_target_identity_on_bound_fixture(damage):
    from factoryline.deep_audit_sarif import _osv_challenge_rows

    _, report, lane, sources, obligation = _osv_challenge_fixture("positive")
    target_package = report["results"][0]["packages"][0]
    if damage == "wrong_package":
        target_package["package"]["name"] = "different-package"
    elif damage == "wrong_version":
        target_package["package"]["version"] = "99.0"
    else:
        target_package = report["results"][0]["packages"].pop(0)
        report["results"][1]["packages"].append(target_package)
    with pytest.raises(RuntimeAuditError, match="signed target package/version absent"):
        _osv_challenge_rows(report, lane, sources, obligation, "positive")


@pytest.mark.parametrize("damage", ["missing", "empty", "duplicate"])
def test_osv_challenges_reject_missing_empty_or_duplicate_manifest_rows(damage):
    from factoryline.deep_audit_sarif import _osv_challenge_rows

    _, report, lane, sources, obligation = _osv_challenge_fixture("positive")
    if damage == "missing":
        report["results"].pop()
    elif damage == "empty":
        report["results"][1]["packages"] = []
    else:
        report["results"].append(deepcopy(report["results"][0]))
    with pytest.raises(RuntimeAuditError):
        _osv_challenge_rows(report, lane, sources, obligation, "positive")


@pytest.mark.parametrize("kind", ["negative", "mutation"])
def test_osv_control_rows_reject_target_advisory_that_survives(kind):
    from factoryline.deep_audit_sarif import _osv_challenge_rows

    _, report, lane, sources, obligation = _osv_challenge_fixture(kind)
    report["results"][0]["packages"][0]["vulnerabilities"] = [_osv_challenge_advisory()]
    with pytest.raises(RuntimeAuditError, match="target advisory survived control"):
        _osv_challenge_rows(report, lane, sources, obligation, kind)


@pytest.mark.parametrize("kind", ["positive", "negative", "mutation"])
def test_trivy_signed_policy_keeps_binary_and_control_config_distinct(kind):
    from factoryline.deep_audit_sarif import _challenge_execution_config_valid_v2

    lane = {
        "engine": "trivy",
        "ruleset_sha256": "a" * 64,
        "native_policy": {
            "config_sha256": "b" * 64,
            "baseline_ignore_sha256": "c" * 64,
        },
        "rule_ids": ["DS001", "DS002"],
        "mutation_config_sha256": {"DS001": "d" * 64},
    }
    execution = {
        "baseline_config_sha256": "c" * 64,
        "effective_config_sha256": "d" * 64 if kind == "mutation" else "c" * 64,
        "mutation": {
            "disabled_rule_id": "DS001",
            "remaining_rule_inventory_sha256": digest(["DS002"]),
        }
        if kind == "mutation"
        else None,
    }
    obligation = {"detector_rule_id": "DS001"}
    identity = ("test-control", kind)
    assert _challenge_execution_config_valid_v2(execution, obligation, identity, lane)
    assert not _challenge_execution_config_valid_v2(
        {**execution, "baseline_config_sha256": lane["ruleset_sha256"]},
        obligation,
        identity,
        lane,
    )
    del lane["native_policy"]
    assert not _challenge_execution_config_valid_v2(
        execution, obligation, identity, lane
    )


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"config_sha256": "b" * 64},
        {"config_sha256": "b" * 64, "baseline_ignore_sha256": "invalid"},
    ],
)
def test_trivy_missing_or_invalid_control_policy_is_incomplete(policy):
    from factoryline.deep_audit_sarif import _challenge_baseline_config_sha256

    assert (
        _challenge_baseline_config_sha256({"engine": "trivy", "native_policy": policy})
        is None
    )


def test_semgrep_negative_challenge_rejects_unrelated_detector_findings():
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    with pytest.raises(RuntimeAuditError, match="signed oracle"):
        _challenge_findings_valid(
            [{"rule_id": "other-rule", "suppressed": False}],
            {},
            {"engine": "semgrep"},
            {"detector_rule_id": "target-rule"},
            "negative",
        )


@pytest.mark.parametrize("kind", ["negative", "mutation"])
def test_semgrep_clean_challenge_has_no_target_finding(kind):
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    _challenge_findings_valid(
        [], {}, {"engine": "semgrep"}, {"detector_rule_id": "target-rule"}, kind
    )


@pytest.mark.parametrize("missing", [True, False])
def test_signed_semgrep_requires_rederived_native_rule_execution(missing):
    from factoryline.deep_audit_sarif import _rule_accounting_gaps
    from test_deep_audit import semgrep_execution_evidence

    evidence, lane, sources, baseline = semgrep_execution_evidence()
    coverage = {"semgrep_rule_execution": evidence}
    assert _rule_accounting_gaps(coverage, lane, sources, baseline) == []
    if missing:
        coverage.clear()
    else:
        evidence["observations"][0]["raw_report_sha256"] = "0" * 64
    assert _rule_accounting_gaps(coverage, lane, sources, baseline) == [
        "SEMGREP_NATIVE_RULE_EXECUTION_UNVERIFIED"
    ]


def test_codeql_retained_evidence_is_verified_and_stays_replay_required(monkeypatch):
    import factoryline.deep_audit_io as deep_audit_io
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    coverage = {"codeql_retained_evidence": {"artifact": "native-bytes"}}
    lane = {"engine": "codeql", "rule_ids": ["js/a"]}
    required = {"src/app.js": "a" * 64}
    received = []

    def verify(observed_coverage, observed_lane, observed_required):
        received.append((observed_coverage, observed_lane, observed_required))

    monkeypatch.setattr(
        deep_audit_io, "verify_codeql_retained_evidence", verify, raising=False
    )

    assert _rule_accounting_gaps(coverage, lane, required) == [
        "CODEQL_NATIVE_REPLAY_REQUIRED"
    ]
    assert received == [(coverage, lane, required)]


def test_codeql_retained_evidence_verifier_rejection_is_unverified(monkeypatch):
    import factoryline.deep_audit_io as deep_audit_io
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    coverage = {"codeql_retained_evidence": {"artifact": "malformed"}}
    lane = {"engine": "codeql", "rule_ids": ["js/a"]}
    required = {"src/app.js": "a" * 64}

    def reject(_coverage, _lane, _required):
        raise RuntimeAuditError("E_CODEQL_RETAINED_EVIDENCE", "invalid evidence")

    monkeypatch.setattr(
        deep_audit_io, "verify_codeql_retained_evidence", reject, raising=False
    )

    assert _rule_accounting_gaps(coverage, lane, required) == [
        "CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"
    ]


def test_osv_retained_evidence_verification_never_clears_host_replay(monkeypatch):
    import factoryline.deep_audit_io as deep_audit_io
    from factoryline.deep_audit_sarif import _osv_retained_evidence_gaps

    coverage = {"osv_native_evidence": {"schema": "factory.osv-native-evidence.v1"}}
    lane = {"engine": "osv"}
    required = {"requirements.txt": "a" * 64}
    report = {"results": []}
    challenges = {"schema": "factory.deep-challenges.v1", "observations": []}
    obligations = [{"id": "osv-target"}]
    received = []

    def verify(*args):
        received.append(args)
        return {"state": "VERIFIED"}

    monkeypatch.setattr(
        deep_audit_io, "verify_osv_retained_evidence", verify, raising=False
    )

    assert _osv_retained_evidence_gaps(
        coverage, lane, required, report, challenges, obligations
    ) == ["OSV_NATIVE_REPLAY_REQUIRED"]
    assert received == [(coverage, lane, required, report, challenges, obligations)]


def test_osv_normalization_requires_host_replay_after_valid_retained_evidence(
    monkeypatch,
):
    import factoryline.deep_audit_io as deep_audit_io
    import factoryline.deep_audit_sarif as deep_audit_sarif

    coverage = {"schema": "factory.deep-coverage.v1"}
    report = {"results": []}
    challenges = {"schema": "factory.deep-challenges.v1", "observations": []}
    sources = {"requirements.txt": "a" * 64}
    lane = {
        "id": "osv-replay-gate",
        "engine": "osv",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
    }
    required = dict(sources)
    monkeypatch.setattr(
        deep_audit_sarif,
        "_worker_artifacts",
        lambda *_args: (report, coverage, challenges, sources),
    )
    monkeypatch.setattr(deep_audit_sarif, "_required_sources", lambda *_args: required)
    monkeypatch.setattr(deep_audit_sarif, "_native_execution_report", lambda *_args: [])
    monkeypatch.setattr(
        deep_audit_sarif,
        "_osv_source_accounting",
        lambda *_args: {"state": "COMPLETE", "measured_paths": sorted(required)},
    )
    monkeypatch.setattr(deep_audit_sarif, "_coverage_gaps", lambda *_args: ([], [], []))
    monkeypatch.setattr(deep_audit_sarif, "_challenge_gaps", lambda *_args: [])
    monkeypatch.setattr(
        deep_audit_io,
        "verify_osv_retained_evidence",
        lambda *_args: {"state": "REPLAY_REQUIRED"},
        raising=False,
    )

    result = deep_audit_sarif.normalize_execution_bundle(
        {}, lane, {"candidate_sha256": "b" * 64}, "osv-replay-gate", []
    )
    assert result["state"] == "INCOMPLETE"
    assert "OSV_NATIVE_REPLAY_REQUIRED" in result["gaps"]


@pytest.mark.parametrize(
    "error",
    [
        RuntimeAuditError("E_OSV_ARTIFACT", "invalid"),
        ValueError("invalid"),
        TypeError("invalid"),
        KeyError("invalid"),
        AttributeError("invalid"),
    ],
)
def test_osv_retained_evidence_rejection_stays_unverified(monkeypatch, error):
    import factoryline.deep_audit_io as deep_audit_io
    from factoryline.deep_audit_sarif import _osv_retained_evidence_gaps

    def reject(*_args):
        raise error

    monkeypatch.setattr(
        deep_audit_io, "verify_osv_retained_evidence", reject, raising=False
    )

    assert _osv_retained_evidence_gaps({}, {"engine": "osv"}, {}, {}, {}, []) == [
        "OSV_NATIVE_ARTIFACTS_UNVERIFIED"
    ]


def test_osv_retained_challenge_rejection_cannot_validate_worker_challenge(
    monkeypatch,
):
    import factoryline.deep_audit_io as deep_audit_io
    from factoryline.deep_audit_sarif import _osv_challenge_native_valid

    def reject(*_args):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "invalid retained evidence")

    monkeypatch.setattr(
        deep_audit_io, "verify_osv_retained_challenge", reject, raising=False
    )

    assert not _osv_challenge_native_valid(
        {"osv_native_evidence": {}},
        {"fixture_manifest": {"requirements.txt": "a" * 64}},
        {"detector_rule_id": "OSV-CVE"},
        ("osv-target", "positive"),
        {"engine": "osv"},
    )


def test_osv_retained_evidence_validates_but_remains_replay_required():
    from factoryline.deep_audit_io import verify_osv_retained_evidence

    coverage, lane, required, report, challenges, obligations = (
        _osv_retained_evidence_fixture()
    )
    verified = verify_osv_retained_evidence(
        coverage, lane, required, report, challenges, obligations
    )
    assert verified["state"] == "REPLAY_REQUIRED"
    assert verified["source_accounting"]["state"] == "COMPLETE"
    assert verified["controls"] == 3


@pytest.mark.parametrize(
    "damage",
    [
        "missing_primary_report",
        "bad_database_identity",
        "oversized_primary_report",
        "source_binding_drift",
        "duplicate_control",
        "missing_control",
    ],
)
def test_osv_retained_evidence_tampering_is_rejected(damage):
    from factoryline.deep_audit_io import (
        LIMIT,
        _osv_native_blob,
        verify_osv_retained_evidence,
    )

    coverage, lane, required, report, challenges, obligations = (
        _osv_retained_evidence_fixture()
    )
    if damage == "missing_primary_report":
        del coverage["osv_native_evidence"]["primary"]["raw_report"]
    elif damage == "bad_database_identity":
        wrong = {
            "path": "/opt/factory/osv-db/foreign/all.zip",
            "sha256": "c" * 64,
            "bytes": 123,
        }
        coverage["osv_native_evidence"]["primary"]["database_identity"] = (
            _osv_native_blob(canonical_bytes(wrong))
        )
    elif damage == "oversized_primary_report":
        coverage["osv_native_evidence"]["primary"]["raw_report"]["bytes"] = LIMIT + 1
    elif damage == "source_binding_drift":
        coverage["osv_native_evidence"]["source_bindings"]["requirements.txt"] = (
            "f" * 64
        )
    elif damage == "duplicate_control":
        challenges["observations"].append(deepcopy(challenges["observations"][0]))
    elif damage == "missing_control":
        challenges["observations"].pop()

    with pytest.raises(RuntimeAuditError, match="E_OSV_ARTIFACT"):
        verify_osv_retained_evidence(
            coverage, lane, required, report, challenges, obligations
        )


@pytest.mark.parametrize(
    "damage",
    [
        "missing_raw_report",
        "missing_effective_config",
        "missing_database_identity",
        "bad_database_identity",
        "oversized_raw_report",
        "source_manifest_drift",
        "unsigned_alias",
        "effective_policy_drift",
        "duplicate_artifact_role",
    ],
)
def test_osv_retained_challenge_tampering_is_rejected(damage):
    from factoryline.deep_audit_io import (
        LIMIT,
        _codeql_native_blob,
        verify_osv_retained_challenge,
    )

    coverage, lane, required, _report, challenges, obligations = (
        _osv_retained_evidence_fixture()
    )
    del coverage, required
    obligation = obligations[0]
    index = 2 if damage == "effective_policy_drift" else 0
    bound = obligation["challenges"][index]
    observation = challenges["observations"][index]
    evidence = observation["osv_native_evidence"]
    if damage == "missing_raw_report":
        del evidence["raw_report"]
    elif damage == "missing_effective_config":
        del evidence["effective_config"]
    elif damage == "missing_database_identity":
        del evidence["database_identity"]
    elif damage == "bad_database_identity":
        wrong_database = {
            "path": "/opt/factory/osv-db/foreign/all.zip",
            "sha256": "c" * 64,
            "bytes": 123,
        }
        wrong_raw = canonical_bytes(wrong_database)
        evidence["database_identity"] = _codeql_native_blob(wrong_raw)
        record = next(
            item
            for item in observation["execution"]["native_artifacts"]
            if item["kind"] == "advisory_db_identity"
        )
        record.update(sha256=sha256_bytes(wrong_raw), bytes=len(wrong_raw))
    elif damage == "oversized_raw_report":
        evidence["raw_report"]["bytes"] = LIMIT + 1
    elif damage == "source_manifest_drift":
        evidence["source_manifest"]["requirements.txt"] = "f" * 64
        evidence["source_manifest_sha256"] = digest(evidence["source_manifest"])
    elif damage == "unsigned_alias":
        raw_report = deepcopy(observation["report"]["native_report"])
        raw_report["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"] = [
            "GHSA-abcd-1234-efgh",
            "OSV-UNSIGNED",
        ]
        raw = canonical_bytes(raw_report)
        evidence["raw_report"] = _codeql_native_blob(raw)
        observation["execution"]["raw_report_sha256"] = sha256_bytes(raw)
        observation["execution"]["native_artifacts"][-1].update(
            sha256=sha256_bytes(raw), bytes=len(raw)
        )
        observation["report"]["native_report"] = raw_report
        observation["observation_sha256"] = digest(observation["report"])
    elif damage == "effective_policy_drift":
        wrong = b"\n"
        evidence["effective_config"] = _codeql_native_blob(wrong)
        observation["execution"]["effective_config_sha256"] = sha256_bytes(wrong)
    elif damage == "duplicate_artifact_role":
        observation["execution"]["native_artifacts"].append(
            deepcopy(observation["execution"]["native_artifacts"][0])
        )

    with pytest.raises(RuntimeAuditError, match="E_OSV_ARTIFACT"):
        verify_osv_retained_challenge(
            observation, lane, bound, obligation, observation["kind"]
        )


def location(line=1, path="app.py"):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }
    }


def report():
    finding = {
        "ruleId": "unsafe",
        "ruleIndex": 0,
        "level": "error",
        "partialFingerprints": {"primary/v1": "stable-id"},
        "locations": [location()],
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {"location": location(), "kinds": ["source"]},
                            {"location": location(2), "kinds": ["sink"]},
                        ]
                    }
                ]
            }
        ],
    }
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Example",
                        "version": "1",
                        "rules": [{"id": "unsafe"}],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [finding],
            }
        ],
    }


def ingest(tmp_path, payload):
    (tmp_path / "app.py").write_text("one\ntwo\n", encoding="utf-8")
    raw = json.dumps(payload).encode()
    (tmp_path / "report.json").write_bytes(raw)
    return normalize_sarif(
        tmp_path,
        {"path": "report.json", "sha256": sha256_bytes(raw)},
        ANALYZER,
        {"app.py": sha256_bytes((tmp_path / "app.py").read_bytes())},
    )


def test_trace_native_identity_and_hashes(tmp_path):
    before = ingest(tmp_path, report())
    changed = report()
    changed["runs"][0]["results"][0]["locations"] = [location(2)]
    after = ingest(tmp_path, changed)
    left, right = before["findings"][0], after["findings"][0]
    assert left["finding_id"] == right["finding_id"]
    assert left["trace_sha256"] != right["trace_sha256"]
    assert left["trace_depth"] == 2
    assert left["flows"][0][0]["kinds"] == ["source"]
    assert before["authority"] == "none"
    assert before["normalized_sha256"] == digest(
        {key: value for key, value in before.items() if key != "normalized_sha256"}
    )


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda r: r.update(version="2.0.0"), "E_SARIF_VERSION"),
        (lambda r: r["runs"][0].update(invocations=[]), "E_SARIF_SHAPE"),
        (
            lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=False),
            "E_ANALYZER_INCOMPLETE",
        ),
        (
            lambda r: r["runs"][0]["invocations"][0].update(executionSuccessful=1),
            "E_ANALYZER_INCOMPLETE",
        ),
        (
            lambda r: r["runs"][0]["tool"]["driver"].update(version="2"),
            "E_ANALYZER_MISMATCH",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(partialFingerprints={}),
            "E_NATIVE_FINGERPRINT",
        ),
        (lambda r: r["runs"][0]["results"][0].update(level="safe"), "E_SARIF_ENUM"),
        (
            lambda r: r["runs"][0]["results"][0].update(baselineState="fixed"),
            "E_SARIF_ENUM",
        ),
        (lambda r: r["runs"][0]["results"][0].update(ruleIndex=1), "E_FIELD"),
        (
            lambda r: r["runs"][0]["results"].append(
                deepcopy(r["runs"][0]["results"][0])
            ),
            "E_DUPLICATE_FINDING",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(
                locations=[location(path="other.py")]
            ),
            "E_TRACE_UNBOUND",
        ),
        (
            lambda r: r["runs"][0]["results"][0].update(
                suppressions=[{"kind": "hidden"}]
            ),
            "E_SARIF_ENUM",
        ),
        (
            lambda r: r["runs"][0]["invocations"][0].update(
                toolConfigurationNotifications=[{"level": "error"}]
            ),
            "E_ANALYZER_INCOMPLETE",
        ),
    ],
)
def test_rejects_bad_evidence(tmp_path, mutate, code):
    payload = report()
    mutate(payload)
    with pytest.raises(RuntimeAuditError, match=code):
        ingest(tmp_path, payload)


@pytest.mark.parametrize(
    "path",
    [
        "../x",
        "/x",
        "C:/x",
        "a\\b",
        "%2e%2e/x",
        "a//b",
        "a/./b",
        "a ",
        "CON",
        "x?y",
        "x:y",
    ],
)
def test_paths_fail_closed(path):
    with pytest.raises(RuntimeAuditError, match="E_PATH_ESCAPE"):
        relative_path(path)


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b"[]", b"{"]
)
def test_strict_json_rejects_ambiguous_data(raw):
    with pytest.raises(RuntimeAuditError):
        strict_json(raw)


def test_source_and_report_drift(tmp_path):
    ingest(tmp_path, report())
    binding = {
        "path": "report.json",
        "sha256": sha256_bytes((tmp_path / "report.json").read_bytes()),
    }
    sources = {"app.py": sha256_bytes((tmp_path / "app.py").read_bytes())}
    altered = report()
    altered["runs"][0]["results"][0]["partialFingerprints"]["primary/v1"] = (
        "different-valid-finding"
    )
    (tmp_path / "report.json").write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)
    (tmp_path / "app.py").write_text("changed")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        normalize_sarif(tmp_path, binding, ANALYZER, sources)


def test_suppression_and_pass_kind_are_preserved_not_accepted_as_canary(tmp_path):
    payload = report()
    payload["runs"][0]["results"][0].update(
        kind="pass", suppressions=[{"kind": "external"}]
    )
    finding = ingest(tmp_path, payload)["findings"][0]
    assert finding["suppressed"] is True
    assert finding["kind"] == "pass"


def test_driver_default_error_is_not_weakened_to_warning(tmp_path):
    payload = report()
    del payload["runs"][0]["results"][0]["level"]
    payload["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {
        "level": "error"
    }
    assert ingest(tmp_path, payload)["findings"][0]["level"] == "error"


def test_reordering_nested_flow_changes_trace_not_identity(tmp_path):
    payload = report()
    before = ingest(tmp_path, payload)["findings"][0]
    payload["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0][
        "locations"
    ].reverse()
    after = ingest(tmp_path, payload)["findings"][0]
    assert before["finding_id"] == after["finding_id"]
    assert before["trace_sha256"] != after["trace_sha256"]


@pytest.mark.parametrize("disabled", [None, "rule-a"])
def test_semgrep_config_inventory_is_derived_from_signed_config(disabled):
    from factoryline.deep_audit_io import canonical_bytes, sha256_bytes
    from factoryline.deep_audit_sarif import _semgrep_config_inventory_valid

    execution = {
        "effective_config_sha256": "a" * 64,
        "mutation": None if disabled is None else {"disabled_rule_id": disabled},
    }
    lane = {"rule_ids": ["rule-a", "rule-b"]}
    raw = canonical_bytes(
        {
            "ruleset_sha256": "a" * 64,
            "rule_ids": [r for r in lane["rule_ids"] if r != disabled],
        }
    )
    artifact = {"sha256": sha256_bytes(raw), "bytes": len(raw)}
    assert _semgrep_config_inventory_valid(execution, lane, artifact)
    assert not _semgrep_config_inventory_valid(
        execution, lane, {**artifact, "sha256": "b" * 64}
    )
    assert not _semgrep_config_inventory_valid(
        execution, lane, {**artifact, "bytes": len(raw) + 1}
    )


def trivy_execution_evidence():
    import base64
    from factoryline.deep_audit_io import canonical_bytes, _trivy_observation

    config, ignore = b"# pinned config\n", b"\n"
    lane = {
        "engine": "trivy",
        "tool_version": "0.68.1",
        "timeout_seconds": 30,
        "ruleset_sha256": "a" * 64,
        "rule_ids": ["DS001", "DS002"],
        "native_artifact_roles": ["policy_inventory", "sarif_report"],
        "native_policy": {
            "config_sha256": sha256_bytes(config),
            "baseline_ignore_sha256": sha256_bytes(ignore),
        },
    }
    sources = {"Dockerfile": "b" * 64}
    sarif = {"runs": [{"results": []}]}
    native = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {"ID": rule, "Status": "PASS"} for rule in lane["rule_ids"]
                ],
                "MisconfSummary": {"Successes": 2, "Failures": 0},
            }
        ],
    }
    argv = [
        "/usr/local/bin/trivy",
        "config",
        "--config",
        "/opt/factory/rules/trivy.yaml",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--ignorefile",
        "/tmp/control.ignore",
        "--format",
        "sarif",
        "--output",
        "/tmp/report.sarif",
        "/src",
    ]
    json_argv = list(argv)
    json_argv[10] = "json"
    json_argv[12] = "/tmp/policy.json"
    json_argv.insert(2, "--include-non-failures")
    facts = {
        "exit_code": 0,
        "timed_out": False,
        "timeout_seconds": 30,
        "duration_ms": 1,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": "c" * 64,
        "stderr_sha256": "d" * 64,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    evidence = {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode(),
        "ignore_base64": base64.b64encode(ignore).decode(),
        "sources": sources,
        "observations": [
            _trivy_observation("sarif", argv, dict(facts), canonical_bytes(sarif)),
            _trivy_observation("json", json_argv, dict(facts), canonical_bytes(native)),
        ],
    }
    return evidence, lane, sources, sarif


def test_trivy_host_rederives_explicit_native_statuses():
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    assert (
        _rule_accounting_gaps({"trivy_rule_execution": evidence}, lane, sources, report)
        == []
    )
    assert _rule_accounting_gaps({}, lane, sources, report) == [
        "TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"
    ]


@pytest.mark.parametrize(
    "tamper",
    [
        "null",
        "missing_rule",
        "duplicate_rule",
        "unsupported_status",
        "summary",
        "missing_source",
        "extra_source",
    ],
)
def test_trivy_host_rejects_resealed_incomplete_native_checks(tamper):
    import base64
    from factoryline.deep_audit_io import canonical_bytes
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    observation = evidence["observations"][1]
    native = json.loads(base64.b64decode(observation["raw_report_base64"]))
    result = native["Results"][0]
    if tamper == "null":
        native["Results"] = None
    elif tamper == "missing_rule":
        result["Misconfigurations"].pop()
        result["MisconfSummary"]["Successes"] = 1
    elif tamper == "duplicate_rule":
        result["Misconfigurations"].append(dict(result["Misconfigurations"][0]))
    elif tamper == "unsupported_status":
        result["Misconfigurations"][0]["Status"] = "SKIPPED"
    elif tamper == "summary":
        result["MisconfSummary"]["Successes"] = 3
    elif tamper == "missing_source":
        sources["nested/Dockerfile"] = "e" * 64
    else:
        result["Target"] = "unbound/Dockerfile"
    raw = canonical_bytes(native)
    observation.update(
        raw_report_base64=base64.b64encode(raw).decode(),
        raw_report_sha256=sha256_bytes(raw),
    )
    assert _rule_accounting_gaps(
        {"trivy_rule_execution": evidence}, lane, sources, report
    ) == ["TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"]


@pytest.mark.parametrize(
    "tamper", ["timeout", "duration", "extra_option", "raw_hash", "config"]
)
def test_trivy_host_rejects_process_or_policy_tampering(tamper):
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    evidence, lane, sources, report = trivy_execution_evidence()
    observation = evidence["observations"][1]
    if tamper == "timeout":
        observation["execution"]["timeout_seconds"] = 31
    elif tamper == "duration":
        observation["execution"]["duration_ms"] = 30001
    elif tamper == "extra_option":
        for item in evidence["observations"]:
            item["argv"].insert(-1, "--skip-files=Dockerfile")
    elif tamper == "raw_hash":
        observation["raw_report_sha256"] = "0" * 64
    else:
        lane["native_policy"]["config_sha256"] = "0" * 64
    assert _rule_accounting_gaps(
        {"trivy_rule_execution": evidence}, lane, sources, report
    ) == ["TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"]


def test_trivy_challenge_artifacts_bind_actual_native_json_bytes():
    import base64
    from factoryline.deep_audit_sarif import _trivy_challenge_native_valid

    evidence, lane, sources, report = trivy_execution_evidence()
    artifacts = [
        {
            "kind": role,
            "sha256": item["raw_report_sha256"],
            "bytes": len(base64.b64decode(item["raw_report_base64"])),
        }
        for item, role in zip(
            evidence["observations"], ("sarif_report", "policy_inventory")
        )
    ]
    execution = {"mutation": None, "native_artifacts": artifacts}
    challenge = {"trivy_rule_execution": evidence, "report": {"native_report": report}}
    assert _trivy_challenge_native_valid(
        execution,
        challenge,
        {"fixture_manifest": sources},
        {"detector_rule_id": "DS001"},
        lane,
    )
    artifacts[1]["bytes"] += 1
    assert not _trivy_challenge_native_valid(
        execution,
        challenge,
        {"fixture_manifest": sources},
        {"detector_rule_id": "DS001"},
        lane,
    )


def test_trivy_clean_negative_rejects_unrelated_failure():
    from factoryline.deep_audit_sarif import _challenge_findings_valid

    with pytest.raises(RuntimeAuditError, match="signed oracle"):
        _challenge_findings_valid(
            [{"rule_id": "DS002", "suppressed": False}],
            {},
            {"engine": "trivy"},
            {"detector_rule_id": "DS001"},
            "negative",
        )


def test_trivy_plain_native_ignore_mutation_has_only_target():
    from factoryline.deep_audit_io import _trivy_mutation, _trivy_ignore_ids

    assert _trivy_mutation(b"\n", "DS001") == b"DS001\n"
    assert _trivy_ignore_ids(b"\n") == []
    assert _trivy_ignore_ids(b"DS001\n") == ["DS001"]
    with pytest.raises(RuntimeAuditError):
        _trivy_mutation(b"DS002\n", "DS001")


def _codeql_inventory_fixture(*, changed=False):
    queries = {
        "codeql/javascript-queries/2/a.ql": "a" * 64,
        "codeql/javascript-queries/2/b.ql": "b" * 64,
    }
    query_ids = {"js/a": next(iter(queries)), "js/b": list(queries)[1]}
    if changed:
        queries["codeql/javascript-queries/2/a.ql"] = "c" * 64
    return {
        "schema": "factory.codeql-query-inventory.v1",
        "suite_sha256": "d" * 64,
        "queries": queries,
        "query_ids": query_ids,
        "query_inventory_sha256": digest(queries),
        "argv": ["codeql", "resolve", "queries"],
        "argv_sha256": "e" * 64,
        "execution": {},
        "raw_resolution_sha256": "f" * 64,
        "claim_boundary": "selection only",
    }


def _codeql_challenge_fixture(kind="positive"):
    from factoryline.deep_audit_sarif import _codeql_challenge_native_valid

    baseline = _codeql_inventory_fixture()
    evidence = deepcopy(baseline)
    suite_hash = baseline["suite_sha256"]
    if kind == "mutation":
        target_path = evidence["query_ids"].pop("js/a")
        evidence["queries"].pop(target_path)
        evidence["query_inventory_sha256"] = digest(evidence["queries"])
        suite_hash = "1" * 64
        evidence["suite_sha256"] = suite_hash
    raw = canonical_bytes(evidence)
    execution = {
        "native_artifacts": [
            {"kind": "sarif_report", "sha256": "2" * 64, "bytes": 3},
            {
                "kind": "query_inventory",
                "sha256": sha256_bytes(raw),
                "bytes": len(raw),
            },
        ],
        "mutation": (
            {
                "disabled_rule_id": "js/a",
                "remaining_rule_inventory_sha256": digest(["js/b"]),
            }
            if kind == "mutation"
            else None
        ),
        "effective_config_sha256": suite_hash,
    }
    challenge = {"codeql_query_inventory": evidence}
    lane = {
        "engine": "codeql",
        "rule_ids": ["js/a", "js/b"],
        "mutation_config_sha256": {"js/a": "1" * 64},
    }
    obligation = {"detector_rule_id": "js/a"}
    bound = {"fixture_manifest": {"route.js": "3" * 64}}
    coverage = {"codeql_query_inventory": baseline}
    valid = _codeql_challenge_native_valid(
        execution, challenge, bound, obligation, ("control", kind), lane, coverage
    )
    return valid, execution, challenge, lane, coverage, obligation, bound


@pytest.mark.parametrize("kind", ["positive", "negative", "mutation"])
def test_codeql_challenge_query_inventory_is_bound_and_exact(kind):
    assert _codeql_challenge_fixture(kind)[0]


@pytest.mark.parametrize("tamper", ["missing", "artifact_hash", "artifact_bytes"])
def test_codeql_challenge_rejects_missing_or_changed_query_artifact(tamper):
    from factoryline.deep_audit_sarif import _codeql_challenge_native_valid

    valid, execution, challenge, lane, coverage, obligation, bound = (
        _codeql_challenge_fixture()
    )
    assert valid
    if tamper == "missing":
        challenge.pop("codeql_query_inventory")
    else:
        artifact = execution["native_artifacts"][1]
        artifact["sha256" if tamper == "artifact_hash" else "bytes"] = (
            "0" * 64 if tamper == "artifact_hash" else artifact["bytes"] + 1
        )
    assert not _codeql_challenge_native_valid(
        execution, challenge, bound, obligation, ("control", "positive"), lane, coverage
    )


@pytest.mark.parametrize("tamper", ["query_drift", "suite_mismatch", "omitted_rule"])
def test_codeql_challenge_rejects_inventory_drift_and_omitted_rule(tamper):
    from factoryline.deep_audit_sarif import _codeql_challenge_native_valid

    valid, execution, challenge, lane, coverage, obligation, bound = (
        _codeql_challenge_fixture("mutation")
        if tamper == "query_drift"
        else _codeql_challenge_fixture()
    )
    assert valid
    evidence = challenge["codeql_query_inventory"]
    if tamper == "query_drift":
        evidence["queries"]["codeql/javascript-queries/2/b.ql"] = "9" * 64
        evidence["query_inventory_sha256"] = digest(evidence["queries"])
    elif tamper == "suite_mismatch":
        execution["effective_config_sha256"] = "8" * 64
    else:
        lane["rule_ids"] = ["js/a"]
    raw = canonical_bytes(evidence)
    execution["native_artifacts"][1].update(sha256=sha256_bytes(raw), bytes=len(raw))
    assert not _codeql_challenge_native_valid(
        execution,
        challenge,
        bound,
        obligation,
        ("control", "mutation" if tamper == "query_drift" else "positive"),
        lane,
        coverage,
    )


@pytest.mark.parametrize(
    "ignore",
    [
        b"DS001\nDS001\n",
        b"DS002\nDS001\n",
        b"misconfigurations: []",
        b"# ignored",
        b"DS001 ",
        b"\xff",
    ],
)
def test_trivy_ignore_rejects_ambiguous_or_extra_policy(ignore):
    from factoryline.deep_audit_io import _trivy_ignore_ids

    with pytest.raises(RuntimeAuditError):
        _trivy_ignore_ids(ignore)


def test_verify_trivy_rule_execution_rederives_native_pass_matrix():
    from factoryline.deep_audit_io import verify_trivy_rule_execution

    evidence, lane, sources, report = trivy_execution_evidence()
    result = verify_trivy_rule_execution(evidence, lane, sources, report)
    assert result == {
        "state": "VERIFIED",
        "checks": {"Dockerfile": {"DS001": "PASS", "DS002": "PASS"}},
        "findings": 0,
    }
    evidence["observations"][1]["raw_report_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="report bytes differ"):
        verify_trivy_rule_execution(evidence, lane, sources, report)

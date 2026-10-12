from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from factoryline.audit_rule_search import AuditRuleSearchError, search_audit_rules
from factoryline.jev_classifier import (
    JevClassificationError,
    build_jev_input,
    classify_retrieval,
    fuse_advisory_scores,
    normalize_jev_result,
)
from factoryline.mcp import dispatch


def _content(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    content = result["content"]
    assert isinstance(content, list)
    return json.loads(content[0]["text"])


def test_search_is_bounded_lane_filtered_and_hash_addressed():
    payload = search_audit_rules(
        {
            "query": "tenant isolation",
            "lane": "authorization_tenant_isolation",
            "includeCrossCutting": False,
            "limit": 3,
        }
    )

    assert payload["marker"] == "MCP_AUDIT_RULE_SEARCH_READ_ONLY"
    assert payload["schema"] == "factory.audit-rule-search.v1"
    assert payload["lane"] == "authorization_tenant_isolation"
    assert payload["includeCrossCutting"] is False
    assert 0 <= payload["returned"] <= 3
    assert payload["totalMatched"] >= payload["returned"]
    assert len(payload["ruleIndexSha256"]) == 64
    assert all(
        rule["lane"] == "authorization_tenant_isolation" for rule in payload["rules"]
    )
    assert all(rule["requiredEvidenceTypes"] for rule in payload["rules"])
    assert payload["authority"] == "none"
    assert payload["ranking"] == "bm25f"
    assert all("retrievalScore" in rule for rule in payload["rules"])


def test_bm25_and_bm25f_are_deterministic_and_explainable():
    bm25 = search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25"})
    bm25f = search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25f"})

    assert bm25["ranking"] == "bm25"
    assert bm25f["ranking"] == "bm25f"
    assert (
        bm25["rules"]
        == search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25"})[
            "rules"
        ]
    )
    assert (
        bm25f["rules"]
        == search_audit_rules({"query": "tenant cache isolation", "ranking": "bm25f"})[
            "rules"
        ]
    )
    assert all(rule["retrievalScore"] > 0 for rule in bm25f["rules"])
    assert bm25f["jevHandoff"]["schema"] == "factory.jev-classification-input.v1"
    assert bm25f["jevHandoff"]["authority"] == "none"


def test_jev_fallback_and_typed_transport_are_fail_closed():
    payload = search_audit_rules({"query": "tenant isolation", "ranking": "bm25f"})
    fallback = classify_retrieval(payload)
    assert fallback["label"] == "HUMAN_REVIEW"
    assert fallback["status"] == "FALLBACK"
    assert fallback["releaseDecision"] is False

    request = build_jev_input(payload)
    normalized = normalize_jev_result(
        {
            "label": "RUN_LANE",
            "probability": 0.8,
            "selectedRuleIds": request["candidateRuleIds"][:1],
            "ruleScores": {request["candidateRuleIds"][0]: 0.8},
            "contextSha256": request["contextSha256"],
        },
        request=request,
    )
    assert normalized["status"] == "ADVISORY"

    def transport(value: dict[str, object]) -> dict[str, object]:
        return {
            "label": "TARGETED_REPAIR",
            "probability": 0.91,
            "selectedRuleIds": value["candidateRuleIds"][:1],
            "ruleScores": {value["candidateRuleIds"][0]: 0.91},
            "contextSha256": value["contextSha256"],
            "requestId": "jev-test-1",
        }

    result = classify_retrieval(payload, transport=transport, model_version="test")
    assert result["status"] == "ADVISORY"
    assert result["label"] == "TARGETED_REPAIR"
    assert result["modelVersion"] == "test"
    assert result["contextSha256"] == request["contextSha256"]

    fused = fuse_advisory_scores(payload, result)
    assert fused["ranking"] == "bm25f+jev-advisory"
    assert fused["authority"] == "none"
    assert fused["releaseDecision"] is False
    assert fused["orderedRuleIds"]

    def bad_transport(value: dict[str, object]) -> dict[str, object]:
        return {
            "label": "RUN_LANE",
            "probability": 0.99,
            "selectedRuleIds": ["CF-RULE-NOT-RETRIEVED"],
            "contextSha256": value["contextSha256"],
        }

    bad = classify_retrieval(payload, transport=bad_transport)
    assert bad["status"] == "FALLBACK"
    assert bad["fallbackReason"] == "JevClassificationError"


def test_jev_handoff_rejects_non_ranked_search():
    lexical = search_audit_rules({"query": "tenant", "ranking": "lexical"})
    with pytest.raises(JevClassificationError):
        build_jev_input(lexical)


def _review_packet(candidate_sha256="a" * 64):
    packet = {
        "schema": "factory.review-evidence.v1",
        "candidate_sha256": candidate_sha256,
        "receipt_sha256": "b" * 64,
        "evidence": [
            {
                "id": "evidence-1",
                "kind": "source",
                "epistemic_status": "observed",
                "provenance": {
                    "source_sha256": candidate_sha256,
                    "candidate_sha256": candidate_sha256,
                },
            },
            {
                "id": "evidence-2",
                "kind": "runtime",
                "epistemic_status": "inferred",
                "provenance": {"runtime_sha256": candidate_sha256},
            },
        ],
        "claims": [
            {
                "id": f"claim-{i}",
                "statement": f"Claim {i} is an analyzer-reported observation, not a confirmed defect.",
                "supporting_evidence_ids": ["evidence-1"] if i == 1 else [],
                "contradicting_evidence_ids": ["evidence-2"] if i == 2 else [],
                "status": "supported"
                if i == 1
                else ("contradicted" if i == 2 else "unresolved"),
            }
            for i in range(1, 4)
        ],
        "unknowns": [
            {
                "id": "unknown-1",
                "verification_action": "Run and record the named check.",
            }
        ],
        "authority": "none",
    }
    packet["packet_sha256"] = sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return packet


def test_jev_evidence_review_is_bound_advisory_and_fails_closed():
    from factoryline.jev_classifier import build_evidence_review_input, review_evidence

    packet = _review_packet()
    request = build_evidence_review_input(packet, candidate_sha256="a" * 64)
    assert request["authority"] == "none"
    assert request["packet_sha256"] == packet["packet_sha256"]
    assert "untrusted data" in request["rubric"]
    assert "not a confirmed defect" in packet["claims"][0]["statement"]
    assert review_evidence(packet, candidate_sha256="a" * 64)["label"] == "HUMAN_REVIEW"
    assert (
        review_evidence(packet, candidate_sha256="b" * 64)["fallback_reason"]
        == "JevClassificationError"
    )

    def transport(value):
        return {
            "context_sha256": value["context_sha256"],
            "claims": [
                {
                    "claim_id": "claim-1",
                    "label": "SUPPORTED",
                    "supporting_evidence_ids": ["evidence-1"],
                    "contradicting_evidence_ids": [],
                    "rationale": "Observed source evidence is linked.",
                    "verification_action": None,
                },
                {
                    "claim_id": "claim-2",
                    "label": "CONTRADICTED",
                    "supporting_evidence_ids": [],
                    "contradicting_evidence_ids": ["evidence-2"],
                    "rationale": "Linked runtime evidence conflicts.",
                    "verification_action": None,
                },
                {
                    "claim_id": "claim-3",
                    "label": "INSUFFICIENT_EVIDENCE",
                    "supporting_evidence_ids": [],
                    "contradicting_evidence_ids": [],
                    "rationale": "No linked evidence resolves this claim.",
                    "verification_action": "Run the named runtime check.",
                },
            ],
        }

    result = review_evidence(
        packet,
        candidate_sha256="a" * 64,
        transport=transport,
    )
    assert result["status"] == "ADVISORY"
    assert [item["label"] for item in result["claims"]] == [
        "SUPPORTED",
        "CONTRADICTED",
        "INSUFFICIENT_EVIDENCE",
    ]
    assert result["request_sha256"] and result["output_sha256"]
    assert result["authority"] == "none" and result["release_decision"] is False
    assert result["unresolved_verification_actions"] == packet["unknowns"]


def test_jev_evidence_review_rejects_invented_references_stale_packet_and_transport_failure():
    from factoryline.jev_classifier import (
        build_evidence_review_input,
        normalize_evidence_review,
        review_evidence,
    )

    packet = _review_packet()
    stale = dict(packet)
    stale["packet_sha256"] = "0" * 64
    with pytest.raises(JevClassificationError):
        build_evidence_review_input(stale, candidate_sha256="a" * 64)
    provenance_mismatch = json.loads(json.dumps(packet))
    provenance_mismatch["evidence"][0]["provenance"]["candidate_sha256"] = "c" * 64
    provenance_mismatch["packet_sha256"] = sha256(
        json.dumps(
            {
                key: value
                for key, value in provenance_mismatch.items()
                if key != "packet_sha256"
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(JevClassificationError):
        build_evidence_review_input(provenance_mismatch, candidate_sha256="a" * 64)
    mismatch = review_evidence(packet, candidate_sha256="b" * 64)
    assert mismatch["status"] == "FALLBACK" and mismatch["label"] == "HUMAN_REVIEW"
    request = build_evidence_review_input(packet, candidate_sha256="a" * 64)
    bad = {
        "context_sha256": request["context_sha256"],
        "claims": [
            {
                "claim_id": "claim-1",
                "label": "SUPPORTED",
                "supporting_evidence_ids": ["invented"],
                "contradicting_evidence_ids": [],
                "rationale": "Fabricated reference.",
                "verification_action": None,
            },
            *[
                {
                    "claim_id": claim,
                    "label": "INSUFFICIENT_EVIDENCE",
                    "supporting_evidence_ids": [],
                    "contradicting_evidence_ids": [],
                    "rationale": "No evidence.",
                    "verification_action": "Verify the claim.",
                }
                for claim in ("claim-2", "claim-3")
            ],
        ],
    }
    with pytest.raises(JevClassificationError):
        normalize_evidence_review(bad, request=request)
    result = review_evidence(
        packet,
        candidate_sha256="a" * 64,
        transport=lambda _: (_ for _ in ()).throw(TimeoutError()),
    )
    assert result["label"] == "HUMAN_REVIEW" and result["status"] == "FALLBACK"


def test_trace_span_review_reuses_closed_evidence_contract_and_keeps_failures_immutable(
    tmp_path,
):
    from test_analysis_evidence import _span_fixture
    from factoryline.analysis_evidence import evaluate_spans
    from factoryline.jev_classifier import (
        build_span_review_input,
        normalize_span_review,
    )

    request, _ = _span_fixture(tmp_path)
    review = build_span_review_input(tmp_path, request)
    assert review["schema"] == "factory.span-semantic-review-input.v1"
    assert review["identity"]["model"] == {
        "id": "review-model",
        "version": "1",
        "artifact_sha256": request["binding_request"]["artifacts"]["model"]["sha256"],
    }
    assert "template" not in json.dumps(review)
    assert review["provider_call"] is False
    claims = review["review_request"]["packet"]["claims"]
    response = {
        "context_sha256": review["review_request"]["context_sha256"],
        "claims": [
            {
                "claim_id": claim["id"],
                "label": "SUPPORTED",
                "supporting_evidence_ids": claim["supporting_evidence_ids"],
                "contradicting_evidence_ids": [],
                "rationale": "The linked local evidence records this outcome.",
                "verification_action": None,
            }
            for claim in claims
        ],
    }
    result = normalize_span_review(
        {"context_sha256": review["context_sha256"], "review": response},
        request=review,
        root=tmp_path,
        binding_request=request,
    )
    assert result["deterministic_state"] == "PASS"
    assert result["deterministic_failures_immutable"] is True
    assert result["authority"] == "none"

    failed_request = json.loads(json.dumps(request))
    failed_request["spans"][0]["numeric"]["value"] = 0.75
    failed = evaluate_spans(tmp_path, failed_request)
    failed_review = build_span_review_input(tmp_path, failed_request)
    failed_claim = next(
        c
        for c in failed_review["review_request"]["packet"]["claims"]
        if c["id"].startswith("span:s1:numeric:")
    )
    assert failed_claim["status"] == "contradicted"
    failed_response = {
        "context_sha256": failed_review["review_request"]["context_sha256"],
        "claims": [
            {
                "claim_id": c["id"],
                "label": "CONTRADICTED"
                if c["status"] == "contradicted"
                else "SUPPORTED",
                "supporting_evidence_ids": c["supporting_evidence_ids"],
                "contradicting_evidence_ids": c["contradicting_evidence_ids"],
                "rationale": "The linked evidence matches the recorded deterministic outcome.",
                "verification_action": None,
            }
            for c in failed_review["review_request"]["packet"]["claims"]
        ],
    }
    failed_result = normalize_span_review(
        {"context_sha256": failed_review["context_sha256"], "review": failed_response},
        request=failed_review,
        root=tmp_path,
        binding_request=failed_request,
    )
    assert failed_result["deterministic_state"] == "FAIL"
    assert failed_result["evaluation_sha256"] == failed["evaluation_sha256"]


def test_span_review_batches_cover_all_spans_and_reject_partial_or_reordered_responses(
    tmp_path,
):
    from test_analysis_evidence import _span_fixture
    from factoryline.jev_classifier import (
        build_span_review_batches,
        normalize_span_review_batches,
        JevClassificationError,
    )

    request, _ = _span_fixture(tmp_path)
    original = request["spans"][0]
    request["spans"] = [{**original, "span_id": f"case_{i}"} for i in range(17)]
    batches = build_span_review_batches(tmp_path, request)
    assert [len(batch["allowed_span_ids"]) for batch in batches["batches"]] == [8, 8, 1]
    assert [
        ident for batch in batches["batches"] for ident in batch["allowed_span_ids"]
    ] == batches["span_ids"]
    assert all("spans" not in batch["evaluation"] for batch in batches["batches"])
    reviews = []
    for batch in batches["batches"]:
        review_request = batch["review_request"]
        reviews.append(
            {
                "context_sha256": batch["context_sha256"],
                "review": {
                    "context_sha256": review_request["context_sha256"],
                    "claims": [
                        {
                            "claim_id": claim["id"],
                            "label": "INSUFFICIENT_EVIDENCE",
                            "supporting_evidence_ids": [],
                            "contradicting_evidence_ids": [],
                            "rationale": "Missing runtime observation.",
                            "verification_action": "Obtain bound observed evidence.",
                        }
                        for claim in review_request["packet"]["claims"]
                    ],
                },
            }
        )
    raw = {"batch_set_sha256": batches["batch_set_sha256"], "reviews": reviews}
    result = normalize_span_review_batches(
        raw, root=tmp_path, binding_request=request, request=batches
    )
    assert result["span_ids"] == batches["span_ids"]
    assert result["semantic_correctness"] == "UNKNOWN_MISSING_TASK_EVIDENCE"
    assert result["provider_call"] is False
    for invalid in (reviews[:-1], list(reversed(reviews))):
        with pytest.raises(JevClassificationError):
            normalize_span_review_batches(
                {**raw, "reviews": invalid},
                root=tmp_path,
                binding_request=request,
                request=batches,
            )


def _span_semantic_fixture(root):
    from test_analysis_evidence import _span_fixture
    import hashlib

    request, _ = _span_fixture(root)
    rubric = json.loads((root / "rubric.json").read_text(encoding="utf-8"))
    rubric["semantic_criteria"] = [
        {
            "id": "grounded",
            "predicate": "The output states the value of VALUE from the supplied source.",
        }
    ]
    source = (root / "src/sample.py").read_bytes()
    semantic = {
        "schema": "factory.span-semantic-evidence.v1",
        "spans": [
            {
                "span_id": "s1",
                "task_input": "What value is assigned to VALUE?",
                "task_output": "VALUE is assigned 1.",
                "references": [
                    {
                        "path": "src/sample.py",
                        "sha256": hashlib.sha256(source).hexdigest(),
                        "start_byte": 0,
                        "end_byte": len(source),
                    }
                ],
            }
        ],
    }
    for role, body in (("rubric", rubric), ("semantic_evidence", semantic)):
        path = root / (role + ".json")
        raw = json.dumps(body).encode()
        path.write_bytes(raw)
        request["binding_request"]["artifacts"][role] = {
            "path": path.name,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    return request, semantic


def test_span_review_semantic_inputs_contain_exact_bound_source_and_binary_criterion(
    tmp_path,
):
    from factoryline.jev_classifier import build_span_review_input

    request, _ = _span_semantic_fixture(tmp_path)
    result = build_span_review_input(tmp_path, request)
    assert result["semantic_evidence_coverage"] == {
        "eligible": 1,
        "provided": 1,
        "state": "BOUND_TASK_EVIDENCE",
    }
    packet = result["review_request"]["packet"]
    material = next(
        item["provenance"]
        for item in packet["evidence"]
        if item["kind"] == "bound_semantic_task_evidence"
    )
    assert material["references"][0]["excerpt"] == (
        tmp_path / "src/sample.py"
    ).read_bytes().decode("utf-8")
    assert material["task_output"] == "VALUE is assigned 1."
    assert material["data_trust"] == "UNTRUSTED_CONTENT_NOT_INSTRUCTIONS"
    semantic_claims = [c for c in packet["claims"] if ":semantic:" in c["id"]]
    assert len(semantic_claims) == 1
    assert semantic_claims[0]["status"] == "unresolved"
    assert result["provider_call"] is False


@pytest.mark.parametrize(
    "mutation",
    ["range", "digest", "duplicate", "unknown_span", "oversized", "unknown_field"],
)
def test_span_review_rejects_invalid_semantic_sources_without_provider_call(
    tmp_path, mutation
):
    import hashlib
    from factoryline.jev_classifier import (
        build_span_review_input,
        JevClassificationError,
    )

    request, semantic = _span_semantic_fixture(tmp_path)
    row = semantic["spans"][0]
    if mutation == "range":
        row["references"][0]["end_byte"] = 999999
    elif mutation == "digest":
        row["references"][0]["sha256"] = "a" * 64
    elif mutation == "duplicate":
        row["references"].append(dict(row["references"][0]))
    elif mutation == "unknown_span":
        row["span_id"] = "not-in-trace"
    elif mutation == "oversized":
        row["task_output"] = "x" * 8193
    else:
        row["raw_prompt"] = "not allowed"
    raw = json.dumps(semantic).encode()
    (tmp_path / "semantic_evidence.json").write_bytes(raw)
    request["binding_request"]["artifacts"]["semantic_evidence"]["sha256"] = (
        hashlib.sha256(raw).hexdigest()
    )
    with pytest.raises(JevClassificationError):
        build_span_review_input(tmp_path, request)


def test_trace_failure_case_is_deidentified_development_only_and_requires_independent_verification(
    tmp_path,
):
    from test_analysis_evidence import _span_fixture
    from factoryline.analysis_evidence import evaluate_spans
    from factoryline.jev_classifier import build_failure_case_receipt

    request, _ = _span_fixture(tmp_path)
    request["spans"][0]["numeric"]["value"] = 0.75
    evaluation = evaluate_spans(tmp_path, request)
    receipt = build_failure_case_receipt(evaluation, span_id="s1")
    serialized = json.dumps(receipt)
    assert '"template"' not in serialized
    assert receipt["assignment"] == {
        "split": "development",
        "development_only": True,
        "holdout_eligible": False,
    }
    assert receipt["repair_verification"]["state"] == "PENDING"
    assert receipt["repair_verification"]["independent_reviewer_required"] is True
    assert receipt["repair_verification"]["source_promotion_authorized"] is False
    evaluation["state"] = "PASS"
    from factoryline.jev_classifier import JevClassificationError

    with pytest.raises(JevClassificationError, match="digest"):
        build_failure_case_receipt(evaluation, span_id="s1")


def test_jev_deep_audit_adapter_binds_native_and_signed_result_shapes():
    from factoryline.analysis_evidence import build_review_evidence
    from factoryline.jev_classifier import review_deep_audit_result

    candidate = "d" * 64
    receipt_core = {"candidate_sha256": candidate, "findings": [], "report_hashes": {}}
    receipt_sha = sha256(
        json.dumps(receipt_core, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {**receipt_core, "receipt_sha256": receipt_sha}
    packet = build_review_evidence(receipt)
    seen = []

    def timeout_transport(request):
        seen.append((request["candidate_sha256"], request["receipt_sha256"]))
        raise TimeoutError()

    signed = review_deep_audit_result(
        {"receipt": receipt, "review_evidence": packet}, transport=timeout_transport
    )
    assert signed["fallback_reason"] == "TimeoutError"
    assert seen[-1] == (candidate, receipt_sha)

    native_packet = _review_packet(candidate)
    native = review_deep_audit_result(
        {"candidate_sha256": candidate, "review_evidence": native_packet},
        transport=timeout_transport,
    )
    assert native["fallback_reason"] == "TimeoutError"
    assert seen[-1] == (candidate, native_packet["receipt_sha256"])


def test_jev_deep_audit_adapter_rejects_conflicting_candidate_or_receipt_bindings():
    from factoryline.jev_classifier import review_deep_audit_result

    packet = _review_packet("e" * 64)
    called = []

    def transport(request):
        called.append(request)

    conflicting_candidate = review_deep_audit_result(
        {
            "candidate_sha256": "f" * 64,
            "receipt": {"candidate_sha256": "e" * 64},
            "review_evidence": packet,
        },
        transport=transport,
    )
    assert conflicting_candidate["fallback_reason"] == "RESULT_CANDIDATE_CONFLICT"
    mismatched_receipt = review_deep_audit_result(
        {
            "receipt": {"candidate_sha256": "e" * 64, "receipt_sha256": "0" * 64},
            "review_evidence": packet,
        },
        transport=transport,
    )
    assert mismatched_receipt["fallback_reason"] == "RESULT_RECEIPT_MISMATCH"
    assert called == []


def test_lexical_mode_preserves_legacy_substring_search():
    payload = search_audit_rules({"query": "e_", "ranking": "lexical", "limit": 2})
    assert payload["ranking"] == "lexical"
    assert all("retrievalScore" not in rule for rule in payload["rules"])


def test_search_inventory_matches_the_six_lane_source_count():
    payload = search_audit_rules({"query": "code factory", "limit": 20})

    from scripts.audit_condition_inventory import inventory

    assert payload["totalMatched"] == inventory()["total_coded_rejection_conditions"]
    assert payload["returned"] == 20


def test_search_can_surface_cross_cutting_rules_and_keeps_context_small():
    payload = search_audit_rules({"query": "e_", "limit": 2})

    assert payload["returned"] <= 2
    assert all(
        "rejectionCondition" in rule and "practicalQuestion" in rule
        for rule in payload["rules"]
    )
    if payload["rules"]:
        assert "signed runtime-audit lane plan" in payload["nextRecommendedStep"]


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"query": "tenant", "limit": 0},
        {"query": "tenant", "lane": "not-a-lane"},
        {"query": "tenant", "includeCrossCutting": "yes"},
        {"query": "tenant", "ranking": "neural"},
        {"query": "tenant", "unexpected": True},
    ],
)
def test_search_rejects_ambiguous_or_unsafe_inputs(arguments: dict[str, object]):
    with pytest.raises(AuditRuleSearchError):
        search_audit_rules(arguments)


def test_search_is_exposed_as_read_only_mcp_tool(tmp_path: Path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.search_audit_rules",
                "arguments": {"query": "migration", "lane": "migration_data_integrity"},
            },
        },
        tmp_path,
    )
    payload = _content(response)

    assert payload["marker"] == "MCP_AUDIT_RULE_SEARCH_READ_ONLY"
    assert payload["lane"] == "migration_data_integrity"


def test_search_mcp_errors_have_stable_marker(tmp_path: Path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "factory.search_audit_rules",
                "arguments": {"query": "tenant", "limit": 99},
            },
        },
        tmp_path,
    )

    assert response["error"]["data"]["marker"] == "MCP_AUDIT_RULE_SEARCH_INVALID"

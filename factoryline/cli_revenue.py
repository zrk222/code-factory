"""Bounded, lazily loaded RevenueForge and AppForge CLI dispatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "revenue"
OWNER = "revenue-appforge-maintainers"


def add_parser(sub: Any) -> None:
    """Register RevenueForge and AppForge subcommands."""
    revenue = sub.add_parser(
        "revenue",
        help="validate and generate human-governed iOS monetization artifacts",
    )
    revenue_sub = revenue.add_subparsers(required=True, dest="revenue_cmd")
    revenue_validate = revenue_sub.add_parser(
        "validate", help="validate products.yaml and deterministic disclosure gates"
    )
    revenue_validate.add_argument("--root", default=".")
    revenue_validate.add_argument("--products", required=True)
    revenue_validate.add_argument("--json", action="store_true")
    revenue_build = revenue_sub.add_parser(
        "build",
        help="generate RevenueKit, paywall, entitlement-server, and evidence scaffolds",
    )
    revenue_build.add_argument("--root", default=".")
    revenue_build.add_argument("--products", required=True)
    revenue_build.add_argument("--out-dir", default=".factory/revenueforge/default")
    revenue_build.add_argument("--json", action="store_true")
    revenue_growth = revenue_sub.add_parser(
        "growth-plan", help="compile provider-write-free Phase 8 growth operations"
    )
    revenue_growth.add_argument("--root", default=".")
    revenue_growth.add_argument("--products", required=True)
    revenue_growth.add_argument("--growth", required=True)
    revenue_growth.add_argument("--out")
    revenue_growth.add_argument("--json", action="store_true")
    revenue_benchmark = revenue_sub.add_parser(
        "benchmark", help="publish a benchmark cell only at k >= 20 distinct apps"
    )
    revenue_benchmark.add_argument("--records", required=True)
    revenue_benchmark.add_argument("--json", action="store_true")
    revenue_replay = revenue_sub.add_parser(
        "replay",
        help="compare build-bound purchase observations with the required lifecycle",
    )
    revenue_replay.add_argument("--root", default=".")
    revenue_replay.add_argument("--products", required=True)
    revenue_replay.add_argument("--events", required=True)
    revenue_replay.add_argument(
        "--out", default=".factory/revenueforge/default/replay.json"
    )
    revenue_replay.add_argument("--json", action="store_true")
    revenue_testflight = revenue_sub.add_parser(
        "testflight-sync",
        help="normalize an authorized local TestFlight feedback export",
    )
    revenue_testflight.add_argument("--root", default=".")
    revenue_testflight.add_argument("--feedback", required=True)
    revenue_testflight.add_argument(
        "--out", default=".factory/revenueforge/default/testflight-inbox.json"
    )
    revenue_testflight.add_argument("--json", action="store_true")
    revenue_matrix = revenue_sub.add_parser(
        "failure-matrix", help="fail closed across observed monetization negative paths"
    )
    revenue_matrix.add_argument("--root", default=".")
    revenue_matrix.add_argument("--products", required=True)
    revenue_matrix.add_argument("--evidence", required=True)
    revenue_matrix.add_argument(
        "--out", default=".factory/revenueforge/default/failure-matrix.json"
    )
    revenue_matrix.add_argument("--json", action="store_true")
    revenue_policy = revenue_sub.add_parser(
        "policy-watch", help="compare hash-bound official Apple policy snapshots"
    )
    revenue_policy.add_argument("--root", default=".")
    revenue_policy.add_argument("--registry", required=True)
    revenue_policy.add_argument("--snapshot", required=True)
    revenue_policy.add_argument(
        "--out", default=".factory/revenueforge/default/policy-drift.json"
    )
    revenue_policy.add_argument("--json", action="store_true")
    revenue_memory_promote = revenue_sub.add_parser(
        "memory-promote",
        help="promote one human-approved receipt-backed operational lesson",
    )
    revenue_memory_promote.add_argument("--root", default=".")
    revenue_memory_promote.add_argument("--entry", required=True)
    revenue_memory_promote.add_argument("--out", required=True)
    revenue_memory_promote.add_argument("--json", action="store_true")
    revenue_memory_query = revenue_sub.add_parser(
        "memory-query", help="retrieve exact-app unexpired evidence lessons"
    )
    revenue_memory_query.add_argument("--root", default=".")
    revenue_memory_query.add_argument("--app-id", required=True)
    revenue_memory_query.add_argument("--journey", required=True)
    revenue_memory_query.add_argument("--at")
    revenue_memory_query.add_argument("--json", action="store_true")
    revenue_billing = revenue_sub.add_parser(
        "billing-reconcile",
        help="reconcile verified StoreKit, Play Billing, and server observations without granting access",
    )
    revenue_billing.add_argument("--root", default=".")
    revenue_billing.add_argument("--products", required=True)
    revenue_billing.add_argument("--events", required=True)
    revenue_billing.add_argument(
        "--out", default=".factory/revenueforge/default/billing-ledger.json"
    )
    revenue_billing.add_argument("--json", action="store_true")
    revenue_experiment = revenue_sub.add_parser(
        "experiment-plan",
        help="compile an approved-by-human, guardrail-bounded experiment plan without starting it",
    )
    revenue_experiment.add_argument("--root", default=".")
    revenue_experiment.add_argument("--products", required=True)
    revenue_experiment.add_argument("--experiment", required=True)
    revenue_experiment.add_argument(
        "--out", default=".factory/revenueforge/default/experiment-plan.json"
    )
    revenue_experiment.add_argument("--json", action="store_true")
    revenue_integrity = revenue_sub.add_parser(
        "integrity",
        help="evaluate manifest, billing, experiment, and baseline integrity without provider actions",
    )
    revenue_integrity.add_argument("--root", default=".")
    revenue_integrity.add_argument("--products", required=True)
    revenue_integrity.add_argument("--ledger", required=True)
    revenue_integrity.add_argument("--experiment")
    revenue_integrity.add_argument("--baseline")
    revenue_integrity.add_argument(
        "--out", default=".factory/revenueforge/default/integrity.json"
    )
    revenue_integrity.add_argument("--json", action="store_true")
    revenue_design = revenue_sub.add_parser(
        "appforge-design",
        help="compile user intent into a story-led seven-discipline iOS design workspace",
    )
    revenue_design.add_argument("--root", default=".")
    revenue_design.add_argument("--brief", required=True)
    revenue_design.add_argument("--out-dir", default=".factory/appforge/design")
    revenue_design.add_argument("--json", action="store_true")
    revenue_evidence_kit = revenue_sub.add_parser(
        "evidence-kit",
        help="create a candidate-bound, non-passing AppForge iOS evidence workspace and novice worklist",
    )
    revenue_evidence_kit.add_argument("--root", default=".")
    revenue_evidence_kit.add_argument("--candidate", required=True)
    revenue_evidence_kit.add_argument("--design-input", required=True)
    revenue_evidence_kit.add_argument("--out-dir", required=True)
    revenue_evidence_kit.add_argument("--json", action="store_true")
    revenue_appforge_init = revenue_sub.add_parser(
        "appforge-init",
        help="capture a user-supplied AppForge mission and exact candidate before design or evidence collection",
    )
    revenue_appforge_init.add_argument("--root", default=".")
    revenue_appforge_init.add_argument("--out-dir", required=True)
    revenue_appforge_init.add_argument("--app-name", required=True)
    revenue_appforge_init.add_argument("--bundle-identifier", required=True)
    revenue_appforge_init.add_argument("--version", required=True)
    revenue_appforge_init.add_argument("--build-number", required=True)
    revenue_appforge_init.add_argument("--source-commit", required=True)
    revenue_appforge_init.add_argument("--audience", required=True)
    revenue_appforge_init.add_argument("--primary-job", required=True)
    revenue_appforge_init.add_argument("--desired-emotion", required=True)
    revenue_appforge_init.add_argument("--json", action="store_true")
    revenue_appforge_status = revenue_sub.add_parser(
        "appforge-status",
        help="read hash-verified local AppForge mission, design, quality, and submission-dossier status",
    )
    revenue_appforge_status.add_argument("--root", default=".")
    revenue_appforge_status.add_argument("--json", action="store_true")
    revenue_app_review = revenue_sub.add_parser(
        "app-review-gate",
        help="fail closed on exact-build Apple policy and rejection-regression evidence gaps",
    )
    revenue_app_review.add_argument("--root", default=".")
    revenue_app_review.add_argument("--contract", required=True)
    revenue_app_review.add_argument("--evidence", required=True)
    revenue_app_review.add_argument(
        "--out", default=".factory/appforge/app-review.json"
    )
    revenue_app_review.add_argument("--json", action="store_true")
    revenue_store_media = revenue_sub.add_parser(
        "store-media-gate",
        help="verify hash-bound iOS Store media against an exact candidate and storyboard journey contract",
    )
    revenue_store_media.add_argument("--root", default=".")
    revenue_store_media.add_argument("--contract", required=True)
    revenue_store_media.add_argument("--evidence", required=True)
    revenue_store_media.add_argument(
        "--out", default=".factory/appforge/store-media.json"
    )
    revenue_store_media.add_argument("--json", action="store_true")
    revenue_quality_audit = revenue_sub.add_parser(
        "quality-audit",
        help="strictly verify user-design, iOS accessibility, UI/UX, and full-stack evidence for one candidate",
    )
    revenue_quality_audit.add_argument("--root", default=".")
    revenue_quality_audit.add_argument("--contract", required=True)
    revenue_quality_audit.add_argument("--evidence", required=True)
    revenue_quality_audit.add_argument(
        "--out", default=".factory/appforge/quality-audit.json"
    )
    revenue_quality_audit.add_argument("--json", action="store_true")
    revenue_submission_assurance = revenue_sub.add_parser(
        "submission-assurance",
        help="produce final iOS Markdown and PDF checklist only after exact-candidate local gates pass",
    )
    revenue_submission_assurance.add_argument("--root", default=".")
    revenue_submission_assurance.add_argument("--contract", required=True)
    revenue_submission_assurance.add_argument("--app-review", required=True)
    revenue_submission_assurance.add_argument("--store-media", required=True)
    revenue_submission_assurance.add_argument("--saas-proof", required=True)
    revenue_submission_assurance.add_argument("--quality-audit", required=True)
    revenue_submission_assurance.add_argument(
        "--oracle-authority",
        help="optional source-bound AppForge Oracle authority file; required when contract marks it required",
    )
    revenue_submission_assurance.add_argument(
        "--out", default=".factory/appforge/submission-assurance.json"
    )
    revenue_submission_assurance.add_argument(
        "--report-dir", default=".factory/appforge/reports"
    )
    revenue_submission_assurance.add_argument("--json", action="store_true")
    revenue_appforge_oracle = revenue_sub.add_parser(
        "appforge-oracle",
        help="verify source-bound AppForge candidate, policy, and gate authority without an Apple action",
    )
    revenue_appforge_oracle.add_argument("--root", default=".")
    revenue_appforge_oracle.add_argument("--authority", required=True)
    revenue_appforge_oracle.add_argument("--out")
    revenue_appforge_oracle.add_argument("--json", action="store_true")
    revenue_device_intent = revenue_sub.add_parser(
        "device-reality-intent",
        help="seal supervised real-device journeys to source-bound AppForge intent without operating a device",
    )
    revenue_device_intent.add_argument("--root", default=".")
    revenue_device_intent.add_argument("--oracle-authority", required=True)
    revenue_device_intent.add_argument("--design-input", required=True)
    revenue_device_intent.add_argument(
        "--journeys",
        required=True,
        help="JSON file containing a required_journeys array",
    )
    revenue_device_intent.add_argument(
        "--transport",
        action="append",
        required=True,
        choices=("manual_physical_device", "phone_harness"),
    )
    revenue_device_intent.add_argument("--out", required=True)
    revenue_device_intent.add_argument("--json", action="store_true")
    revenue_device_reality = revenue_sub.add_parser(
        "device-reality-gate",
        help="verify supervised device evidence against a sealed AppForge intent envelope; never operates a device",
    )
    revenue_device_reality.add_argument("--root", default=".")
    revenue_device_reality.add_argument("--intent-envelope", required=True)
    revenue_device_reality.add_argument("--evidence", required=True)
    revenue_device_reality.add_argument(
        "--out", default=".factory/appforge/device-reality.json"
    )
    revenue_device_reality.add_argument("--json", action="store_true")
    revenue_appforge_eas = revenue_sub.add_parser(
        "appforge-eas",
        help="validate a candidate-bound EAS profile handoff without reading credentials or submitting to Apple",
    )
    revenue_appforge_eas.add_argument("--root", default=".")
    revenue_appforge_eas.add_argument("--candidate", required=True)
    revenue_appforge_eas.add_argument("--eas-json", required=True)
    revenue_appforge_eas.add_argument("--build-profile", required=True)
    revenue_appforge_eas.add_argument("--submit-profile", required=True)
    revenue_appforge_eas.add_argument("--out")
    revenue_appforge_eas.add_argument("--json", action="store_true")
    revenue_rehearsal = revenue_sub.add_parser(
        "appforge-rehearse",
        help="seal a credential-free Fastlane, App Store Connect CLI, Cider, Swiftlane, or Zealot release rehearsal without running a provider",
    )
    revenue_rehearsal.add_argument("--root", default=".")
    revenue_rehearsal.add_argument("--candidate", required=True)
    revenue_rehearsal.add_argument("--submission-assurance", required=True)
    revenue_rehearsal.add_argument("--profile", required=True)
    revenue_rehearsal.add_argument(
        "--out", default=".factory/appforge/release-rehearsal.json"
    )
    revenue_rehearsal.add_argument("--json", action="store_true")
    revenue_native_surface = revenue_sub.add_parser(
        "appforge-native-surface",
        help="verify a source-bound adaptive Apple-surface preflight without building, rendering, or contacting Apple",
    )
    revenue_native_surface.add_argument("--root", default=".")
    revenue_native_surface.add_argument("--candidate", required=True)
    revenue_native_surface.add_argument("--contract", required=True)
    revenue_native_surface.add_argument("--evidence", required=True)
    revenue_native_surface.add_argument(
        "--out", default=".factory/appforge/native-surface.json"
    )
    revenue_native_surface.add_argument("--json", action="store_true")
    revenue_surface_matrix = revenue_sub.add_parser(
        "appforge-surface-matrix",
        help="generate a sealed iPhone/iPad accessibility configuration plan without operating a device",
    )
    revenue_surface_matrix.add_argument("--root", default=".")
    revenue_surface_matrix.add_argument("--candidate", required=True)
    revenue_surface_matrix.add_argument("--native-surface", required=True)
    revenue_surface_matrix.add_argument(
        "--out", default=".factory/appforge/surface-matrix.json"
    )
    revenue_surface_matrix.add_argument("--json", action="store_true")
    revenue_storefront_story = revenue_sub.add_parser(
        "appforge-storefront-story",
        help="verify source-bound Store screenshot story coverage and claim references without generating or uploading media",
    )
    revenue_storefront_story.add_argument("--root", default=".")
    revenue_storefront_story.add_argument("--candidate", required=True)
    revenue_storefront_story.add_argument("--store-media", required=True)
    revenue_storefront_story.add_argument("--contract", required=True)
    revenue_storefront_story.add_argument("--evidence", required=True)
    revenue_storefront_story.add_argument(
        "--out", default=".factory/appforge/storefront-story.json"
    )
    revenue_storefront_story.add_argument("--json", action="store_true")
    revenue_fastlane_capture = revenue_sub.add_parser(
        "appforge-fastlane-capture",
        help="seal a capture-only Fastlane Snapshot contract without running Xcode, Fastlane, or Apple actions",
    )
    revenue_fastlane_capture.add_argument("--root", default=".")
    revenue_fastlane_capture.add_argument("--candidate", required=True)
    revenue_fastlane_capture.add_argument("--surface-matrix", required=True)
    revenue_fastlane_capture.add_argument("--storefront-story", required=True)
    revenue_fastlane_capture.add_argument("--contract", required=True)
    revenue_fastlane_capture.add_argument(
        "--out", default=".factory/appforge/fastlane-capture.json"
    )
    revenue_fastlane_capture.add_argument("--json", action="store_true")
    revenue_submission_integrity = revenue_sub.add_parser(
        "appforge-submission-integrity",
        help="fail closed on loose AppForge iPhone/iPad capture requirements without creating media",
    )
    revenue_submission_integrity.add_argument("--root", default=".")
    revenue_submission_integrity.add_argument("--candidate", required=True)
    revenue_submission_integrity.add_argument("--contract", required=True)
    revenue_submission_integrity.add_argument(
        "--out", default=".factory/appforge/submission-integrity.json"
    )
    revenue_submission_integrity.add_argument("--json", action="store_true")
    revenue_mobile_evidence = revenue_sub.add_parser(
        "appforge-mobile-evidence",
        help="normalize source-bound iOS/Android tool evidence into one candidate-bound readiness receipt without running tools or providers",
    )
    revenue_mobile_evidence.add_argument("--root", default=".")
    revenue_mobile_evidence.add_argument("--candidate", required=True)
    revenue_mobile_evidence.add_argument("--contract", required=True)
    revenue_mobile_evidence.add_argument("--evidence", required=True)
    revenue_mobile_evidence.add_argument(
        "--out", default=".factory/appforge/mobile-evidence.json"
    )
    revenue_mobile_evidence.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one RevenueForge/AppForge command and render its receipt."""
    from .app_review_gate import verify_app_review_readiness
    from .appforge_design import appforge_design_projection, compile_appforge_design
    from .appforge_device_reality import (
        create_device_reality_intent_envelope,
        verify_device_reality,
    )
    from .appforge_eas import verify_eas_preflight
    from .appforge_evidence_kit import create_evidence_kit, initialize_appforge
    from .appforge_fastlane_capture import create_fastlane_capture_contract
    from .appforge_mobile_evidence import verify_mobile_evidence
    from .appforge_native_surface import verify_native_surface
    from .appforge_oracle import verify_appforge_oracle_authority
    from .appforge_quality_audit import verify_quality_audit
    from .appforge_release_rehearsal import create_release_rehearsal
    from .appforge_store_media import StoreMediaError, verify_store_media
    from .appforge_storefront_story import verify_storefront_story
    from .appforge_submission_assurance import verify_submission_assurance
    from .appforge_submission_integrity import verify_submission_integrity
    from .appforge_surface_matrix import create_surface_matrix
    from .revenue_evidence import (
        evaluate_failure_matrix,
        promote_evidence_memory,
        query_evidence_memory,
        replay_purchase_journey,
        sync_testflight_evidence,
        watch_policy_drift,
    )
    from .revenue_integrity import (
        evaluate_revenue_integrity,
        plan_revenue_experiment,
        reconcile_billing_events,
    )
    from .revenueforge import (
        RevenueForgeError,
        benchmark_cell,
        build_revenue_bundle,
        plan_growth,
        validate_products,
    )

    try:
        root = Path(getattr(args, "root", ".")).resolve()
        if args.revenue_cmd == "validate":
            payload = validate_products(root, Path(args.products))
        elif args.revenue_cmd == "build":
            payload = build_revenue_bundle(root, Path(args.products), Path(args.out_dir))
        elif args.revenue_cmd == "growth-plan":
            payload = plan_growth(root, Path(args.products), Path(args.growth))
            if args.out:
                out = Path(args.out)
                out = out.resolve() if out.is_absolute() else (root / out).resolve()
                out.relative_to(root)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                payload = {**payload, "path": str(out)}
        elif args.revenue_cmd == "benchmark":
            payload = benchmark_cell(json.loads(Path(args.records).read_text(encoding="utf-8-sig")))
        elif args.revenue_cmd == "replay":
            payload = replay_purchase_journey(root, Path(args.products), Path(args.events), Path(args.out))
        elif args.revenue_cmd == "testflight-sync":
            payload = sync_testflight_evidence(root, Path(args.feedback), Path(args.out))
        elif args.revenue_cmd == "failure-matrix":
            payload = evaluate_failure_matrix(root, Path(args.products), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "policy-watch":
            payload = watch_policy_drift(root, Path(args.registry), Path(args.snapshot), Path(args.out))
        elif args.revenue_cmd == "memory-promote":
            payload = promote_evidence_memory(root, Path(args.entry), Path(args.out))
        elif args.revenue_cmd == "memory-query":
            payload = query_evidence_memory(root, args.app_id, args.journey, args.at)
        elif args.revenue_cmd == "billing-reconcile":
            payload = reconcile_billing_events(root, Path(args.products), Path(args.events), Path(args.out))
        elif args.revenue_cmd == "experiment-plan":
            payload = plan_revenue_experiment(root, Path(args.products), Path(args.experiment), Path(args.out))
        elif args.revenue_cmd == "integrity":
            payload = evaluate_revenue_integrity(
                root,
                Path(args.products),
                Path(args.ledger),
                Path(args.experiment) if args.experiment else None,
                Path(args.baseline) if args.baseline else None,
                Path(args.out),
            )
        elif args.revenue_cmd == "app-review-gate":
            payload = verify_app_review_readiness(root, Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "store-media-gate":
            payload = verify_store_media(root, Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "quality-audit":
            payload = verify_quality_audit(root, Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "submission-assurance":
            payload = verify_submission_assurance(
                root,
                Path(args.contract),
                Path(args.app_review),
                Path(args.store_media),
                Path(args.saas_proof),
                Path(args.quality_audit),
                Path(args.out),
                Path(args.report_dir),
                Path(args.oracle_authority) if args.oracle_authority else None,
            )
        elif args.revenue_cmd == "appforge-oracle":
            payload = verify_appforge_oracle_authority(root, Path(args.authority), out=Path(args.out) if args.out else None)
        elif args.revenue_cmd == "device-reality-intent":
            journey_path = Path(args.journeys).resolve() if Path(args.journeys).is_absolute() else (root / Path(args.journeys)).resolve()
            journey_path.relative_to(root)
            if not journey_path.is_file() or journey_path.stat().st_size > 1_048_576:
                raise RevenueForgeError(
                    "APPFORGE_DEVICE_REALITY_INPUT_UNAVAILABLE",
                    "journeys input must be a regular workspace JSON file up to 1 MiB",
                )
            journeys_input = json.loads(journey_path.read_text(encoding="utf-8-sig"))
            journeys = journeys_input.get("required_journeys") if isinstance(journeys_input, dict) else journeys_input
            payload = create_device_reality_intent_envelope(
                root, Path(args.oracle_authority), Path(args.design_input), journeys, args.transport, Path(args.out)
            )
        elif args.revenue_cmd == "device-reality-gate":
            payload = verify_device_reality(root, Path(args.intent_envelope), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "appforge-eas":
            payload = verify_eas_preflight(
                root, Path(args.candidate), Path(args.eas_json), args.build_profile, args.submit_profile,
                out=Path(args.out) if args.out else None,
            )
        elif args.revenue_cmd == "appforge-rehearse":
            payload = create_release_rehearsal(root, Path(args.candidate), Path(args.submission_assurance), Path(args.profile), Path(args.out))
        elif args.revenue_cmd == "appforge-native-surface":
            payload = verify_native_surface(root, Path(args.candidate), Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "appforge-surface-matrix":
            payload = create_surface_matrix(root, Path(args.candidate), Path(args.native_surface), Path(args.out))
        elif args.revenue_cmd == "appforge-storefront-story":
            payload = verify_storefront_story(root, Path(args.candidate), Path(args.store_media), Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "appforge-fastlane-capture":
            payload = create_fastlane_capture_contract(root, Path(args.candidate), Path(args.surface_matrix), Path(args.storefront_story), Path(args.contract), Path(args.out))
        elif args.revenue_cmd == "appforge-submission-integrity":
            payload = verify_submission_integrity(root, Path(args.candidate), Path(args.contract), Path(args.out))
        elif args.revenue_cmd == "appforge-mobile-evidence":
            payload = verify_mobile_evidence(root, Path(args.candidate), Path(args.contract), Path(args.evidence), Path(args.out))
        elif args.revenue_cmd == "evidence-kit":
            payload = create_evidence_kit(root, Path(args.candidate), Path(args.design_input), Path(args.out_dir))
        elif args.revenue_cmd == "appforge-init":
            payload = initialize_appforge(
                root,
                Path(args.out_dir),
                app_name=args.app_name,
                bundle_identifier=args.bundle_identifier,
                version=args.version,
                build_number=args.build_number,
                source_commit=args.source_commit,
                audience=args.audience,
                primary_job=args.primary_job,
                desired_emotion=args.desired_emotion,
            )
        elif args.revenue_cmd == "appforge-status":
            payload = appforge_design_projection(root)
        else:
            payload = compile_appforge_design(root, Path(args.brief), Path(args.out_dir))
    except (RevenueForgeError, StoreMediaError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        error = {
            "schema": "factory.revenueforge.error.v1",
            "marker": "REVENUEFORGE_REFUSED",
            "code": getattr(exc, "code", "REVENUEFORGE_INPUT_INVALID"),
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if args.json
            else f"revenue {args.revenue_cmd} refused: {error['code']}: {exc}",
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(payload.get("marker", "REVENUEFORGE_OK"))
        if payload.get("receipt_sha256"):
            print(f"receipt     : {payload['receipt_sha256']}")
        print("authority   : no App Store write, offer send, experiment promotion, review publication, deployment, or credential access")
    return 0 if payload.get("ok", True) else 1

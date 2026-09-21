"""Bounded, lazily loaded RevenueForge and AppForge CLI dispatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "revenue"
OWNER = "revenue-appforge-maintainers"


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

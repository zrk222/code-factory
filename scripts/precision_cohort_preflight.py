"""Run hash-bound startup checks for every cohort arm before permitting launch."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import random
import re
import subprocess
import sys
import tempfile

SCHEMA = "factory.precision-cohort-startup.v1"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def bound_path(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe captured path")
    selected = (root / path).resolve()
    if not selected.is_relative_to(root.resolve()):
        raise ValueError("captured path escapes root")
    return selected


def startup(scanner, workspace, profile, expected_files):
    """Read source/config through the frozen API; never execute target modules."""
    if platform.python_version() != profile["python"] or sys.flags.optimize:
        raise ValueError("interpreter differs from registered profile")
    for name, version in profile["dependencies"].items():
        if importlib.metadata.version(name) != version:
            raise ValueError("dependency differs from registered profile: " + name)
    scanner = Path(scanner).resolve()
    sys.path.insert(0, str(scanner))
    from factoryline import cli, review_audits as audit

    if not Path(cli.__file__).resolve().is_relative_to(scanner):
        raise ValueError("frozen scanner import identity mismatch")
    workspace = Path(workspace).resolve()
    files = audit._security_source_files(workspace)
    if {p.relative_to(workspace).as_posix() for p in files} != set(expected_files):
        raise ValueError("source inventory differs from registered capture")
    if len(files) > audit._validate_source_file_limit(None):
        raise ValueError("source inventory exceeds scanner capacity")
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        try:
            ast.parse(
                audit._security_source_bytes(workspace, relative), filename=relative
            )
        except (SyntaxError, ValueError, RecursionError) as error:
            raise ValueError(
                "unsupported captured Python syntax: " + relative
            ) from error
    _, collection = audit._pytest_collection_config(
        workspace, files, allow_unknown=profile["security_only"] is True
    )
    return {"state": "PASS", "files": len(files), "collection": collection}


def scanner_bundles(root, protocol, bindings):
    scanners = {}
    for arm in ("baseline", "candidate"):
        bundle = bound_path(root, protocol["scanner"][arm])
        manifest = bundle / "manifest.json"
        if digest(manifest) != protocol["scanner"][arm + "_manifest_sha256"]:
            raise ValueError("scanner manifest seal changed")
        bindings[str(manifest)] = digest(manifest)
        for name, expected in json.loads(manifest.read_text()).items():
            path = bound_path(bundle / "scanner", name)
            if digest(path) != expected:
                raise ValueError("frozen scanner source changed")
            bindings[str(path)] = expected
        scanners[arm] = bundle / "scanner"
    return scanners


def inputs(study):
    study = Path(study).resolve()
    root = study.parents[1]
    registration = study / "registration.json"
    protocol = json.loads(registration.read_text(encoding="utf-8-sig"))
    if digest(registration) != (study / "registration.sha256").read_text().strip():
        raise ValueError("registration seal mismatch")
    capture = study / "source-capture.json"
    rows = json.loads(capture.read_text(encoding="utf-8-sig"))["repositories"]
    bindings = {
        str(registration): digest(registration),
        str(capture): digest(capture),
        str(Path(__file__).resolve()): digest(__file__),
    }
    controller = study / "study.py"
    if digest(controller) != protocol["controllers"]["study.py"]:
        raise ValueError("registered run controller changed")
    bindings[str(controller)] = digest(controller)
    scanners = scanner_bundles(root, protocol, bindings)
    jobs = []
    for row in rows:
        if row["state"] != "CAPTURED":
            continue
        source = bound_path(root, row["source_root"])
        if not source.is_relative_to(study / "capture"):
            raise ValueError("unexpected cohort source root")
        for item in row["sources"]:
            path = bound_path(source, item["path"])
            if digest(path) != item["sha256"]:
                raise ValueError("captured source/configuration changed")
            bindings[str(path)] = item["sha256"]
        expected = [item["path"] for item in row["sources"] if item["kind"] == "python"]
        for arm, scanner in scanners.items():
            jobs.append(
                {
                    "repository": row["repository"],
                    "arm": arm,
                    "scanner": str(scanner),
                    "workspace": str(source),
                    "profile": protocol["scanner"]["profile"],
                    "expected_files": expected,
                }
            )
    identities = [(r["repository"], r["arm"]) for r in jobs]
    if not all((bool(identities), len(set(identities)) == len(identities))):
        raise ValueError("empty or duplicate cohort identities")
    return jobs, bindings, controller


def worker(job):
    try:
        command = [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "--worker",
            json.dumps(job),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=90, check=False
        )
        observation = (
            json.loads(result.stdout)
            if result.returncode == 0 and not result.stderr
            else {
                "state": "BLOCKED",
                "error": result.stderr.strip() or result.stdout.strip(),
            }
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        observation = {
            "state": "BLOCKED",
            "error": type(error).__name__ + ": " + str(error),
        }
    return {"repository": job["repository"], "arm": job["arm"], **observation}


def preflight(study):
    jobs, bindings, controller, checks = [], {}, None, []
    unchanged, error = False, None
    try:
        jobs, bindings, controller = inputs(study)
        with ThreadPoolExecutor(max_workers=2) as pool:
            checks = list(pool.map(worker, jobs))
        unchanged = all(digest(path) == expected for path, expected in bindings.items())
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        error = type(exc).__name__ + ": " + str(exc)
    receipt = {
        "schema": SCHEMA,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "state": "PASS"
        if not error
        and unchanged
        and checks
        and all(r["state"] == "PASS" for r in checks)
        else "BLOCKED",
        "study": str(Path(study).resolve()),
        "controller": str(controller),
        "expected": [[r["repository"], r["arm"]] for r in jobs],
        "inputs": bindings,
        "checks": checks,
        "inputs_unchanged": unchanged,
        "error": error,
        "boundary": "Static startup readiness only; no predictions, precision, complete audit or release claim.",
    }
    receipt["receipt_sha256"] = canonical(receipt)
    return receipt


def validate(receipt):
    if (receipt.get("schema"), receipt.get("state")) != (SCHEMA, "PASS"):
        raise ValueError("cohort startup preflight has not passed")
    core = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    if receipt.get("receipt_sha256") != canonical(core):
        raise ValueError("preflight receipt seal mismatch")
    jobs, bindings, controller = inputs(receipt["study"])
    identities = [[row["repository"], row["arm"]] for row in jobs]
    observed = [[row["repository"], row["arm"]] for row in receipt["checks"]]
    if not all((receipt["expected"] == identities, observed == identities)):
        raise ValueError("missing, duplicate or unexpected startup check")
    if receipt["inputs"] != bindings or receipt["controller"] != str(controller):
        raise ValueError("stale startup receipt")
    if receipt["inputs_unchanged"] is not True or any(
        r["state"] != "PASS" for r in receipt["checks"]
    ):
        raise ValueError("failed startup check")
    current = preflight(receipt["study"])
    if current["state"] != "PASS" or any(
        current[key] != receipt[key]
        for key in ("expected", "inputs", "checks", "controller")
    ):
        raise ValueError("startup inputs, inventory or execution profile changed")
    return controller


def launch(receipt):
    controller = validate(receipt)
    return subprocess.run(
        [sys.executable, "-B", str(controller), "run"],
        cwd=controller.parents[2],
        check=False,
    ).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker")
    parser.add_argument("--study", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--launch", action="store_true")
    args = parser.parse_args()
    if args.worker:
        job = json.loads(args.worker)
        try:
            print(
                json.dumps(
                    startup(
                        job["scanner"],
                        job["workspace"],
                        job["profile"],
                        job["expected_files"],
                    )
                )
            )
            return 0
        except Exception as error:
            print(type(error).__name__ + ": " + str(error), file=sys.stderr)
            return 2
    if args.study is None or args.receipt is None:
        parser.error("--study and --receipt are required")
    if args.launch:
        receipt = json.loads(args.receipt.read_text())
        if receipt.get("study") != str(args.study.resolve()):
            raise ValueError("receipt belongs to another study")
        return launch(receipt)
    receipt = preflight(args.study)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "state": receipt["state"],
                "checks": len(receipt["checks"]),
                "blocked": [r for r in receipt["checks"] if r["state"] != "PASS"],
            }
        )
    )
    return 0 if receipt["state"] == "PASS" else 2


ARM_G_PACKET_INSTRUCTIONS = "For each item, decide whether the marked line (>) is a real instance of the claimed weakness: attacker- or user-influenced data can reach it in a realistic deployment of this library or application, with no effective validation in the shown or implied code. If a span is present, it gives the start column, end-line offset, and end column. Use context_wide and file_header_imports when the short context is not enough. Answer TP, FP or UNCLEAR, with one sentence of reasoning. Judge each item on its own; do not look up advisories, fixes, repositories or other labels, and do not use the web."

ARM_G_DIRECTORY = Path("docs/evidence/precision-tier-prereg-20261127")
ARM_G_VERDICTS = {"TP", "FP", "UNCLEAR"}
ARM_G_SOURCE_KINDS = {"request", "cli", "env", "file", "message", "public_api_param"}
ARM_G_RULES = "deploy/deep-adapters/rules/semgrep-pattern-limited.yml"
ARM_G_PROFILE = "docs/evidence/recall-registered-exposed-161-profile.json"
ARM_G_WEAKNESSES = (
    ("shell-command|command-injection", "OS command injection"),
    ("sql", "SQL injection"),
    ("path|archive|tarfile|zip", "Path traversal"),
    ("html|xss|innerhtml|template", "XSS / HTML injection"),
    ("deserializ", "Unsafe deserialization"),
    (
        "tls|hostname-verification|certificate",
        "Disabled TLS / certificate verification",
    ),
    ("inclusion", "File inclusion"),
    ("code-injection|eval", "Code injection"),
)
ARM_G_IMPORT = re.compile(
    r"^\s*(import\b|from\s+\S+\s+import\b|require\b|use\s|using\s|include|#include|package\s)"
)


def arm_g_json(path):
    """Read one immutable-input snapshot and derive the digest from the same bytes."""
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def arm_g_write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=1)
        stream.write("\n")
    return digest(path)


def arm_g_lock(repo, engine=None):
    lock, lock_sha256 = arm_g_json(repo / ARM_G_DIRECTORY / "run-lock.json")
    pins = {
        **lock["repo_files"],
        **{f"scripts/{name}": sha for name, sha in lock["scorer"]["files"].items()},
    }
    for name, expected in pins.items():
        if digest(bound_path(repo, name)) != expected:
            raise ValueError(f"Arm G lock mismatch: {name}")
    if engine is not None and digest(engine) not in lock["engine"]["sha256"].values():
        raise ValueError("Arm G engine lock mismatch")
    return lock, lock_sha256


def arm_g_packet_item(alert, repository, tier, workdir):
    root = Path(alert["root"]).resolve()
    if not root.is_relative_to(workdir.resolve()):
        raise ValueError("review source lies outside the score work directory")
    raw = bound_path(root, alert["path"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != alert["source_sha256"]:
        raise ValueError("review source digest differs")
    rule = alert["rule"].split("pins.")[-1]
    line = alert["line"]
    lines = raw.decode("utf-8", "replace").split("\n")
    span = alert.get("span")
    if not isinstance(line, int) or not 1 <= line <= len(lines):
        raise ValueError("review location lies outside the captured source")
    item_id = hashlib.sha256(
        json.dumps([alert["case"], alert["path"], line, rule, span]).encode()
    ).hexdigest()[:12]

    def context(lo, hi):
        return "\n".join(
            f"{i + 1:5d}{'>' if i + 1 == line else ' '} {lines[i]}"
            for i in range(max(0, lo), min(len(lines), hi))
        )

    item = {
        "item": item_id,
        "repository": repository,
        "file": alert["path"],
        "line": line,
        "span": span,
        "claimed_weakness": next(
            (
                weakness
                for pattern, weakness in ARM_G_WEAKNESSES
                if re.search(pattern, rule)
            ),
            rule.split(".", 1)[-1],
        ),
        "context": context(line - 6, line + 5),
        "context_wide": context(line - 41, line + 40),
        "file_header_imports": "\n".join(
            f"{i + 1:5d}  {text}"
            for i, text in enumerate(lines[:200])
            if ARM_G_IMPORT.match(text)
        )[:2500],
    }
    key = {
        "case": alert["case"],
        "file": alert["path"],
        "line": line,
        "rule": rule,
        "span": span,
        "tier": tier[rule],
        "on_fix_hunk": alert["on_fix_hunk"],
        "source_sha256": alert["source_sha256"],
    }
    return item, key


def arm_g_packet(args):
    import yaml

    lock, lock_sha256 = arm_g_lock(args.repo)
    score, score_sha256 = arm_g_json(args.score)
    if score_sha256 != args.score_sha256:
        raise ValueError("Arm G score digest mismatch")
    rules_sha256 = lock["repo_files"][ARM_G_RULES]
    if (
        score.get("schema") != "factory.recall-result.v1"
        or score.get("ruleset_sha256") != rules_sha256
        or score.get("profile_sha256") != lock["repo_files"][ARM_G_PROFILE]
        or score.get("engine", {}).get("executable_sha256")
        not in lock["engine"]["sha256"].values()
        or score.get("scope") != "ecosystem"
    ):
        raise ValueError("Arm G score receipt differs from the locked scan")
    rules = yaml.safe_load((args.repo / ARM_G_RULES).read_bytes())["rules"]
    tier = {
        rule["id"]: "lead"
        if (rule.get("metadata") or {}).get("confidence") == "LOW"
        else "finding"
        for rule in rules
    }
    repositories = {case["ghsa"]: case["repository"] for case in score["cases"]}
    if len(repositories) != len(score["cases"]):
        raise ValueError("duplicate Arm G score case")
    with tempfile.TemporaryDirectory(prefix="arm-g-", dir=args.run.parent) as temporary:
        staging = Path(temporary)
        export = staging / "alerts.json"
        subprocess.run(
            [
                "node",
                str((args.repo / "scripts" / "recall_harness.mjs").resolve()),
                "review-alerts",
                "--score",
                str(args.score.resolve()),
                "--score-sha256",
                score_sha256,
                "--workdir",
                str(args.workdir.resolve()),
                "--out",
                str(export.resolve()),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        alerts, alerts_sha256 = arm_g_json(export)
        items, key = [], {}
        for alert in alerts:
            if alert["rules_sha256"] != rules_sha256:
                raise ValueError("review export uses different rules")
            item, entry = arm_g_packet_item(
                alert, repositories[alert["case"]], tier, args.workdir
            )
            if item["item"] in key:
                raise ValueError("duplicate Arm G alert identity")
            items.append(item)
            key[item["item"]] = entry
        items.sort(key=lambda item: item["item"])
        random.Random(args.seed).shuffle(items)
        packet = {
            "schema": "factory.label-packet.v2",
            "cohort": args.run.name,
            "seed": args.seed,
            "instructions": ARM_G_PACKET_INSTRUCTIONS,
            "items": items,
        }
        packet_sha256 = arm_g_write(staging / "packet.json", packet)
        key_sha256 = arm_g_write(
            staging / "key.json",
            {
                "packet_sha256": packet_sha256,
                "rules_sha256": rules_sha256,
                "score_sha256": score_sha256,
                "alerts_sha256": alerts_sha256,
                "lock_sha256": lock_sha256,
                "key": key,
            },
        )
        if args.run.exists():
            raise ValueError("Arm G packet already exists")
        staging.rename(args.run)
    return {
        "items": len(items),
        "packet_sha256": packet_sha256,
        "key_sha256": key_sha256,
        "score_sha256": score_sha256,
        "alerts_sha256": alerts_sha256,
    }


def arm_g_index(rows):
    result = {}
    for row in rows:
        item = row["item"]
        if not isinstance(item, str) or not item or item in result:
            raise ValueError("missing or duplicate Arm G item identity")
        result[item] = row
    return result


def arm_g_reviews(path, packet_sha256, items):
    document, _ = arm_g_json(path)
    if document.get("packet_sha256") != packet_sha256:
        raise ValueError(f"{path.name} belongs to a different packet")
    labels = arm_g_index(document["labels"])
    if labels.keys() != items.keys():
        raise ValueError(f"{path.name} does not cover exactly its assigned items")
    if any(
        row["verdict"] not in ARM_G_VERDICTS or not row["reason"].strip()
        for row in labels.values()
    ):
        raise ValueError(f"{path.name} contains an invalid verdict or empty rationale")
    return labels


def arm_g_disagreements(run, packet, packet_sha256, items):
    opus = arm_g_reviews(run / "labels-opus.json", packet_sha256, items)
    fable = arm_g_reviews(run / "labels-fable.json", packet_sha256, items)
    disputes = []
    for item in sorted(items):
        if opus[item]["verdict"] != fable[item]["verdict"]:
            disputes.append(
                {
                    **items[item],
                    "reviewer_a": {
                        key: opus[item][key] for key in ("verdict", "reason")
                    },
                    "reviewer_b": {
                        key: fable[item][key] for key in ("verdict", "reason")
                    },
                }
            )
    return (
        {"instructions": packet["instructions"], "disagreements": disputes},
        opus,
        fable,
    )


def arm_g_votes(run, model, items, packet_sha256):
    lines = {
        item: {
            int(match)
            for match in re.findall(
                r"^\s*(\d+)[> ]",
                row["context_wide"] + "\n" + row.get("file_header_imports", ""),
                re.M,
            )
        }
        for item, row in items.items()
    }
    votes = dict.fromkeys(items, 0)
    for reviewer in "abc":
        rows = []
        for path in sorted(run.glob(f"triage-{model}{reviewer}-part*.json")):
            document, _ = arm_g_json(path)
            if document.get("packet_sha256") != packet_sha256:
                raise ValueError(f"{path.name} belongs to a different triage packet")
            rows.extend(document["triage"])
        for item, row in arm_g_index(rows).items():
            if item not in items or row["decision"] not in {"REPORT", "SUPPRESS"}:
                raise ValueError("invalid Arm G triage item or decision")
            if row["decision"] != "REPORT":
                continue
            try:
                source, entry, sink = (
                    int(row[key]) for key in ("source_line", "entry_line", "sink_line")
                )
            except (TypeError, ValueError, KeyError):
                continue
            if (
                row.get("source_kind") in ARM_G_SOURCE_KINDS
                and sink == items[item]["line"]
                and {source, entry} <= lines[item]
            ):
                votes[item] += 1
    return votes


def arm_g_endpoint(args, packet, packet_sha256, items):
    key_document, key_sha256 = arm_g_json(args.run / "key.json")
    score, score_sha256 = arm_g_json(args.score)
    if (
        key_sha256 != args.key_sha256
        or key_document["packet_sha256"] != packet_sha256
        or key_document["score_sha256"] != score_sha256
        or key_document["key"].keys() != items.keys()
    ):
        raise ValueError("Arm G score, packet and sealed key bindings differ")
    expected, opus, fable = arm_g_disagreements(args.run, packet, packet_sha256, items)
    observed, adjudication_sha256 = arm_g_json(args.run / "adjudication-packet.json")
    if observed != expected:
        raise ValueError(
            "Arm G adjudication packet differs from the current reviewer inputs"
        )
    disagreements = arm_g_index(observed["disagreements"])
    ao = (
        arm_g_reviews(
            args.run / "adjudication-opus.json", adjudication_sha256, disagreements
        )
        if disagreements
        else {}
    )
    af = (
        arm_g_reviews(
            args.run / "adjudication-fable.json", adjudication_sha256, disagreements
        )
        if disagreements
        else {}
    )
    lo = {item: row["verdict"] for item, row in opus.items()}
    lf = {item: row["verdict"] for item, row in fable.items()}
    final = lo.copy()
    for item in disagreements:
        final[item] = (
            ao[item]["verdict"]
            if ao[item]["verdict"] == af[item]["verdict"]
            else "UNCLEAR"
        )
    haiku = arm_g_votes(args.run, "H", items, packet_sha256)
    stage2, stage2_sha256 = arm_g_json(args.run / "stage2.json")
    if stage2 != {
        **packet,
        "items": [row for row in packet["items"] if haiku[row["item"]] >= 2],
    }:
        raise ValueError("Arm G stage 2 packet differs from the current stage 1 votes")
    sonnet = arm_g_votes(args.run, "S", arm_g_index(stage2["items"]), stage2_sha256)
    return arm_g_metrics(
        items,
        key_document["key"],
        final,
        lo,
        lf,
        haiku,
        sonnet,
        score["summary"]["scored"],
    )


def arm_g_main(argv):
    parser = argparse.ArgumentParser(prog="precision_cohort_preflight.py arm-g")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify-lock")
    verify.add_argument("repo", type=Path)
    verify.add_argument("engine", type=Path)
    build = commands.add_parser("packet")
    for field in ("repo", "run", "score", "workdir"):
        build.add_argument(field, type=Path)
    build.add_argument("score_sha256")
    build.add_argument("--seed", default="20261127")
    for command in ("stage2", "adjudication", "score"):
        stage = commands.add_parser(command)
        stage.add_argument("run", type=Path)
        if command == "score":
            stage.add_argument("score", type=Path)
            stage.add_argument("key_sha256")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-lock":
            _, lock_sha256 = arm_g_lock(args.repo, args.engine)
            result = {"state": "LOCK VERIFIED", "lock_sha256": lock_sha256}
        elif args.command == "packet":
            result = arm_g_packet(args)
        else:
            packet, packet_sha256 = arm_g_json(args.run / "packet.json")
            items = arm_g_index(packet["items"])
            if args.command == "adjudication":
                document, _, _ = arm_g_disagreements(
                    args.run, packet, packet_sha256, items
                )
                result = {
                    "items": len(document["disagreements"]),
                    "packet_sha256": arm_g_write(
                        args.run / "adjudication-packet.json", document
                    ),
                }
            elif args.command == "stage2":
                haiku = arm_g_votes(args.run, "H", items, packet_sha256)
                selected = [row for row in packet["items"] if haiku[row["item"]] >= 2]
                result = {
                    "items": len(selected),
                    "packet_sha256": arm_g_write(
                        args.run / "stage2.json", {**packet, "items": selected}
                    ),
                }
            else:
                result = arm_g_endpoint(args, packet, packet_sha256, items)
        print(json.dumps(result))
        return 0
    except (
        AttributeError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Arm G: {error}", file=sys.stderr)
        return 2


def arm_g_metrics(items, key, final, lo, lf, H, S, scored):
    from scipy.stats import beta

    G = {i for i in items if H[i] >= 2 and S[i] == 3}

    def lb(k, n):
        return float(beta.ppf(0.05, k, n - k + 1)) if k else 0.0

    def ub(k, n):
        return float(beta.ppf(0.95, k + 1, n - k)) if k < n else 1.0

    def read_out(ids, unclear_fp=False):
        tp = sum(final[i] == "TP" for i in ids)
        fp = sum(
            final[i] == "FP" or (unclear_fp and final[i] == "UNCLEAR") for i in ids
        )
        return tp, fp, (tp / (tp + fp) if tp + fp else None)

    def verdict(ids):
        tp, fp, p = read_out(ids)
        n = tp + fp
        by = defaultdict(list)
        for i in ids:
            if final[i] != "UNCLEAR":
                by[key[i]["case"]].append(final[i] == "TP")
        ctp = sum(sum(v) > len(v) / 2 for v in by.values())
        cn = len(by)  # one outcome per case; ties are FP
        repo_tp = Counter(items[i]["repository"] for i in ids if final[i] == "TP")
        top = repo_tp.most_common(1)[0][0] if repo_tp else None
        drop = read_out([i for i in ids if items[i]["repository"] != top])[2]
        ufp = read_out(ids, True)[2]
        robust = (
            cn >= 5
            and drop is not None
            and drop >= 0.49
            and ufp is not None
            and ufp >= 0.49
        )

        def level(cut, bound):
            return (
                n >= 5
                and p >= cut
                and lb(tp, n) > bound
                and ctp / cn >= cut
                and lb(ctp, cn) > bound
                and robust
            )

        return {
            "findings": len(ids),
            "decided": n,
            "TP": tp,
            "FP": fp,
            "UNCLEAR": len(ids) - n,
            "precision": p,
            "cp_lb95_one_sided": lb(tp, n) if n else None,
            "cp_ub95_one_sided": ub(tp, n) if n else None,
            "case_level": {
                "cases": cn,
                "tp_cases": ctp,
                "cp_lb95": lb(ctp, cn) if cn else None,
            },
            "drop_top_tp_repository": {
                "repository_dropped": bool(top),
                "precision": drop,
            },
            "unclear_as_fp": ufp,
            "six_x_point": bool(n >= 5 and p >= 0.49),
            "eight_x_point": bool(n >= 5 and p >= 0.656),
            "six_x_confirmed": level(0.49, 0.246),
            "eight_x_confirmed": level(0.656, 0.328),
            "six_x_strong": bool(n >= 5 and lb(tp, n) >= 0.49 and robust),
            "eight_x_strong": bool(n >= 5 and lb(tp, n) >= 0.656 and robust),
            "not_met": bool(n >= 5 and ub(tp, n) < 0.49),
            "inconclusive_small_n": n < 5,
        }

    hit = {key[i]["case"] for i in items if key[i]["on_fix_hunk"]}
    kept = {key[i]["case"] for i in G if key[i]["on_fix_hunk"]}
    return {
        "arm_G": verdict(G),
        "recall": {
            "scored_cases": scored,
            "hit_cases_all_alerts": len(hit),
            "hit_cases_kept_as_findings": len(kept),
        },
        "secondary": {
            "arm_F_haiku_3of3": verdict({i for i in items if H[i] == 3}),
            "haiku_3of3_sonnet_2of3": verdict(
                {i for i in items if H[i] == 3 and S[i] >= 2}
            ),
            "overall_precision_all_alerts": read_out(list(items))[2],
            "tiers": {
                t: read_out([i for i in items if key[i]["tier"] == t])[2]
                for t in ("finding", "lead")
            },
        },
        "label_agreement": {
            "agree": sum(lo[i] == lf[i] for i in items),
            "items": len(items),
        },
    }


if __name__ == "__main__":
    raise SystemExit(arm_g_main(sys.argv[2:]) if sys.argv[1:2] == ["arm-g"] else main())

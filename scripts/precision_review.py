#!/usr/bin/env python3
"""Blinded precision review for the pattern lane: packet, judge, adjudicate, ledger.

The steps below turn scanner alerts into per-rule precision with stated
uncertainty, so a rule's confidence comes from labeled evidence rather than
from an author's guess.

  packet      alerts (+ source trees) -> blinded packet + sealed key
  judge       packet + two reviewers' labels -> disagreements for a judge
  adjudicate  packet + key + labels + judge -> adjudicated rows
  ledger      adjudicated files -> per-rule precision ledger (Wilson, Beta)
  check       ledger + rules YAML -> fail if a rule claims more than evidence

Alert input is JSON: a list of {"case", "root", "path", "line", "rule",
"on_fix_hunk"} rows, where root/path names the scanned file. Reviewers see
only the case, file, line, claimed weakness and source context; the rule and
whether the line is on the fix hunk stay in the key until labels are in.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

VERDICTS = ("TP", "FP", "UNCLEAR")
FAMILIES = (
    ({"CWE-22", "CWE-23", "CWE-73", "CWE-59"}, "path traversal"),
    ({"CWE-79", "CWE-80", "CWE-116"}, "XSS / HTML injection"),
    ({"CWE-78", "CWE-77", "CWE-88"}, "command injection"),
    ({"CWE-89"}, "SQL injection"),
    ({"CWE-502"}, "unsafe deserialization"),
    ({"CWE-295", "CWE-319"}, "TLS / transport verification"),
)
INSTRUCTIONS = (
    "For each item, decide whether the marked line (>) is a real instance of the claimed "
    "weakness: attacker- or user-influenced data can reach it in a realistic deployment of "
    "this library or application, with no effective validation in the shown or implied code. "
    "Answer TP, FP or UNCLEAR, with one sentence of reasoning. Judge each item on its own; do "
    "not look up advisories, fixes or other labels."
)
# A rule is eligible for the default tier only when the lower Wilson bound of
# its adjudicated precision clears this, on at least MIN_DECIDED decided alerts.
DEFAULT_TIER_LOWER_BOUND = 0.80
REVIEW_TIER_LOWER_BOUND = 0.30
MIN_DECIDED = 20


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value) -> str:
    data = (json.dumps(value, indent=1, sort_keys=False) + "\n").encode()
    path.write_bytes(data)
    return sha256_bytes(data)


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def wilson(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    """Wilson score interval for a binomial proportion, as fractions."""
    if total <= 0:
        return None
    phat = successes / total
    denominator = 1 + z * z / total
    centre = phat + z * z / (2 * total)
    margin = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
    return [round((centre - margin) / denominator, 4), round((centre + margin) / denominator, 4)]


def beta_mean(successes: int, failures: int) -> float:
    """Posterior mean under a uniform Beta(1, 1) prior."""
    return round((successes + 1) / (successes + failures + 2), 4)


def weakness(cwes: list[str]) -> str:
    found = set(cwes)
    for members, label in FAMILIES:
        if found & members:
            return label
    return ", ".join(sorted(found)) or "unspecified"


def rule_cwes(rules_path: Path) -> dict[str, list[str]]:
    import yaml  # PyYAML ships with the factory extra.

    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
    return {rule["id"]: list(rule.get("metadata", {}).get("cwe", [])) for rule in rules}


def item_id(alert: dict) -> str:
    raw = f"{alert['case']}|{alert['path']}|{alert['line']}|{alert['rule']}"
    return sha256_bytes(raw.encode())[:12]


def context(root: Path, path: str, line: int, radius: int = 5) -> str:
    source = (root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    first, last = max(0, line - 1 - radius), min(len(source), line + radius)
    return "\n".join(
        f"{index + 1:5}{'>' if index + 1 == line else ' '} {source[index]}" for index in range(first, last)
    )


def stratified(alerts: list[dict], per_rule: int, seed: int) -> list[dict]:
    """At most per_rule alerts per rule, drawn with a fixed seed, then shuffled."""
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        by_rule[alert["rule"]].append(alert)
    rng = random.Random(seed)
    chosen = []
    for rule in sorted(by_rule):
        rows = sorted(by_rule[rule], key=item_id)
        chosen.extend(rows if len(rows) <= per_rule else rng.sample(rows, per_rule))
    rng.shuffle(chosen)
    return chosen


def build_packet(args) -> None:
    cwes = rule_cwes(Path(args.rules))
    unique = {}
    for alert in read_json(Path(args.alerts)):
        unique.setdefault(item_id(alert), alert)
    chosen = stratified(list(unique.values()), args.per_rule, args.seed)
    items, key = [], {}
    for alert in chosen:
        identity = item_id(alert)
        items.append({"item": identity, "repository_case": alert["case"], "file": alert["path"],
                      "line": alert["line"], "claimed_weakness": weakness(cwes.get(alert["rule"], [])),
                      "context": context(Path(alert["root"]), alert["path"], alert["line"])})
        key[identity] = {"rule": alert["rule"], "on_fix_hunk": bool(alert.get("on_fix_hunk"))}
    packet = {"schema": "factory.label-packet.v1", "cohort": args.cohort, "seed": args.seed,
              "per_rule_cap": args.per_rule, "instructions": INSTRUCTIONS, "items": items}
    digest = write_json(Path(args.out), packet)
    write_json(Path(args.key), {"packet_sha256": digest, "key": key})
    print(json.dumps({"items": len(items), "rules": dict(Counter(k["rule"] for k in key.values())),
                      "packet_sha256": digest}))


def labels_by_position(packet: dict, labels: dict) -> list[dict]:
    rows = labels["labels"]
    if [row["item"] for row in rows] != [item["item"] for item in packet["items"]]:
        raise SystemExit("labels do not follow the packet's item order")
    for row in rows:
        if row["verdict"] not in VERDICTS:
            raise SystemExit(f"invalid verdict {row['verdict']!r} for {row['item']}")
    return rows


def build_judge(args) -> None:
    packet = read_json(Path(args.packet))
    first = labels_by_position(packet, read_json(Path(args.labels[0])))
    second = labels_by_position(packet, read_json(Path(args.labels[1])))
    disagreements = [
        {"position": index, **item,
         "reviewer_1": {"verdict": a["verdict"], "reason": a.get("reason", "")},
         "reviewer_2": {"verdict": b["verdict"], "reason": b.get("reason", "")}}
        for index, (item, a, b) in enumerate(zip(packet["items"], first, second))
        if a["verdict"] != b["verdict"]
    ]
    digest = write_json(Path(args.out), {"schema": "factory.judge-packet.v1",
                                         "packet_sha256": sha256_bytes(Path(args.packet).read_bytes()),
                                         "disagreements": disagreements})
    print(json.dumps({"positions": len(first), "disagreements": len(disagreements), "judge_packet_sha256": digest}))


def adjudicate(args) -> None:
    packet_bytes = Path(args.packet).read_bytes()
    packet = json.loads(packet_bytes)
    sealed = read_json(Path(args.key))
    if sealed["packet_sha256"] != sha256_bytes(packet_bytes):
        raise SystemExit("key belongs to a different packet")
    first = labels_by_position(packet, read_json(Path(args.labels[0])))
    second = labels_by_position(packet, read_json(Path(args.labels[1])))
    judged = {row["position"]: row for row in read_json(Path(args.judge))["verdicts"]} if args.judge else {}
    rows, final = [], {}
    for index, (item, a, b) in enumerate(zip(packet["items"], first, second)):
        if a["verdict"] == b["verdict"]:
            verdict, judge = a["verdict"], None
        elif index in judged:
            verdict = judge = judged[index]["verdict"]
        else:
            raise SystemExit(f"disagreement at position {index} has no judge verdict")
        if final.setdefault(item["item"], verdict) != verdict:
            raise SystemExit(f"duplicate item {item['item']} received different final verdicts")
        rows.append({"position": index, "item": item["item"], "case": item["repository_case"],
                     "file": item["file"], "line": item["line"], **sealed["key"][item["item"]],
                     "reviewer_1": a["verdict"], "reviewer_2": b["verdict"], "judge": judge, "final": verdict})
    out = {"schema": "factory.adjudicated-precision.v2", "packet_sha256": sealed["packet_sha256"],
           "reviewers": args.reviewer, "judge": args.judge_name,
           "independence": "AI reviewers and judge unless stated otherwise; independence from AI is unestablished",
           "agreed_positions": sum(row["judge"] is None for row in rows), "positions": len(rows), "rows": rows}
    print(json.dumps({"digest": write_json(Path(args.out), out), "unique": len(final),
                      "verdicts": dict(Counter(final.values()))}))


def tier_for(tp: int, fp: int) -> str:
    decided = tp + fp
    bounds = wilson(tp, decided)
    if decided < MIN_DECIDED or bounds is None:
        return "unqualified"
    if bounds[0] >= DEFAULT_TIER_LOWER_BOUND:
        return "default"
    return "review" if bounds[0] >= REVIEW_TIER_LOWER_BOUND else "retire"


def ledger(args) -> None:
    per_rule: dict[str, Counter] = defaultdict(Counter)
    sources = []
    seen = set()
    for path in args.adjudicated:
        data = read_json(Path(path))
        sources.append({"file": str(path), "sha256": sha256_bytes(Path(path).read_bytes()),
                        "independence": data.get("independence", "unstated")})
        for row in data["rows"]:
            identity = (row.get("case") or row.get("repository_case"), row["file"], row["line"], row["rule"])
            if identity in seen:
                continue
            seen.add(identity)
            per_rule[row["rule"]][row["final"]] += 1
    rules = {}
    for rule, counts in sorted(per_rule.items()):
        tp, fp = counts["TP"], counts["FP"]
        rules[rule] = {"tp": tp, "fp": fp, "unclear": counts["UNCLEAR"], "decided": tp + fp,
                       "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                       "wilson95": wilson(tp, tp + fp), "beta_mean": beta_mean(tp, fp),
                       "evidence_tier": tier_for(tp, fp)}
    out = {"schema": "factory.rule-confidence.v1",
           "policy": {"default_tier_wilson_lower": DEFAULT_TIER_LOWER_BOUND,
                      "review_tier_wilson_lower": REVIEW_TIER_LOWER_BOUND,
                      "minimum_decided_alerts": MIN_DECIDED},
           "sources": sources, "rules": rules}
    print(json.dumps({"digest": write_json(Path(args.out), out), "rules": len(rules)}))


def check(args) -> int:
    """Rules may claim confidence only as far as the ledger supports it."""
    import yaml

    confidence = read_json(Path(args.ledger))["rules"]
    problems = []
    for rule in yaml.safe_load(Path(args.rules).read_text(encoding="utf-8"))["rules"]:
        claimed = rule.get("metadata", {}).get("confidence")
        evidence = confidence.get(rule["id"], {})
        tier = evidence.get("evidence_tier", "unqualified")
        if claimed == "HIGH" and tier != "default":
            problems.append(f"{rule['id']}: claims HIGH confidence but evidence tier is {tier}")
        if tier == "retire":
            problems.append(f"{rule['id']}: evidence tier is retire ({evidence.get('tp')}/{evidence.get('decided')})")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    packet = commands.add_parser("packet")
    packet.add_argument("--alerts", required=True)
    packet.add_argument("--rules", required=True)
    packet.add_argument("--cohort", required=True)
    packet.add_argument("--per-rule", type=int, default=30)
    packet.add_argument("--seed", type=int, required=True)
    packet.add_argument("--out", required=True)
    packet.add_argument("--key", required=True)
    judge = commands.add_parser("judge")
    judge.add_argument("--packet", required=True)
    judge.add_argument("--labels", nargs=2, required=True)
    judge.add_argument("--out", required=True)
    adjudicated = commands.add_parser("adjudicate")
    adjudicated.add_argument("--packet", required=True)
    adjudicated.add_argument("--key", required=True)
    adjudicated.add_argument("--labels", nargs=2, required=True)
    adjudicated.add_argument("--reviewer", nargs=2, required=True)
    adjudicated.add_argument("--judge")
    adjudicated.add_argument("--judge-name")
    adjudicated.add_argument("--out", required=True)
    led = commands.add_parser("ledger")
    led.add_argument("--adjudicated", nargs="+", required=True)
    led.add_argument("--out", required=True)
    checked = commands.add_parser("check")
    checked.add_argument("--ledger", required=True)
    checked.add_argument("--rules", required=True)
    args = parser.parse_args(argv)
    handlers = {"packet": build_packet, "judge": build_judge, "adjudicate": adjudicate, "ledger": ledger}
    if args.command == "check":
        return check(args)
    handlers[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Installed-command five-brick ProofLab smoke used by integration CI."""
from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factoryline.contract import Receipt, ensure_layout
from factoryline.passport import build_passport, verify_passport
from factoryline.proof import build_trace
from factoryline.challenge import challenge_trace


EXAMPLE = ROOT / "examples" / "prooflab"


def run(command: list[str], cwd: Path) -> None:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=180)
    if proc.returncode:
        raise RuntimeError(f"{' '.join(command)} failed\n{proc.stdout}\n{proc.stderr}")


def run_module(module: str, arguments: list[str], cwd: Path) -> None:
    run([sys.executable, "-m", module, *arguments], cwd)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="prooflab-e2e-") as temp:
        root = Path(temp)
        shutil.copytree(EXAMPLE, root, dirs_exist_ok=True)
        challenges = root / ".factory" / "challenges"
        challenges.mkdir(parents=True)
        run_module("specline.cli", ["challenge", "prooflab", "--root", str(root), "--out", str(challenges / "specline.json")], root)
        run_module("forgeline.cli", ["challenge", "prooflab", str(root / "prooflab.ssat.yaml"), "--root", str(root), "--out", str(challenges / "forgeline.json")], root)
        run_module("hsf.cli", ["init", "prooflab"], root)
        run_module("hsf.cli", ["challenge", "specs/prooflab.yaml", "--output", str(challenges / "hsf.json")], root)
        run_module("prestige_design.cli", ["challenge", str(root / "prooflab.html"), "--purpose", "developer", "--workflow", "product", "--feature", "prooflab", "--out", str(challenges / "prestige.json")], root)
        run_module("prestige_design.cli", ["tokens", "lint", str(root / "prooflab.html"), "--design", str(root / "DESIGN.md"), "--strict"], root)
        run_module("prestige_design.cli", ["verify-tokens", str(root / "prooflab.html"), "--design", str(root / "DESIGN.md"), "--out", str(challenges / "prestige-tokens.json")], root)

        ensure_layout(root)
        for brick, filename, stage in (
            ("specline", "specline.json", "challenge"),
            ("forgeline", "forgeline.json", "challenge"),
            ("hsf", "hsf.json", "challenge"),
            ("prestige", "prestige.json", "challenge"),
            ("prestige", "prestige-tokens.json", "design_tokens"),
        ):
            challenge = challenges / filename
            Receipt(
                module=brick,
                stage=stage,
                feature="prooflab",
                ok=json.loads(challenge.read_text())["passed"],
                outputs={"paths": [str(challenge)]},
            ).write(root)
        trace = build_trace(root, "prooflab")
        factory_challenge = challenge_trace(root / trace["trace_path"], root=root)
        factory_path = challenges / "factoryline.json"
        factory_path.write_text(json.dumps(factory_challenge, indent=2), encoding="utf-8")
        challenge_paths = sorted(challenges.glob("*.json"))
        passport = build_passport(root, "prooflab", root / trace["trace_path"], challenge_paths)
        result = verify_passport(Path(passport["paths"]["json"]))
        if not result["valid"]:
            raise RuntimeError(json.dumps(result, indent=2))
        print(json.dumps({
            "verified": True,
            "trace_nodes": passport["trace_nodes"],
            "challenge_stages": [f"{item['brick']}:{item['stage']}" for item in passport["challenges"]],
            "mermaid": passport["paths"]["mermaid"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

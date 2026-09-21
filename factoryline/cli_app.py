"""Lazy CLI boundary for deterministic app scaffolding."""

from __future__ import annotations

import json
from pathlib import Path


_APP_STACK_CHOICES = (
    "nextjs-fastapi-postgres",
    "react-fastapi-postgres",
    "react-fastapi-sqlite",
)


def add_parser(sub) -> None:
    """Register the PRD and prompt app-scaffolding commands."""
    s = sub.add_parser("app", help="PRD-to-full-stack app builder")
    app_sub = s.add_subparsers(dest="app_cmd", required=True)
    app_sub.add_parser("stacks", help="list supported deterministic starter stacks")
    a_prd = app_sub.add_parser(
        "from-prd", help="scaffold an app from a PRD markdown file"
    )
    _add_scaffold_arguments(a_prd, "prd")
    a_prompt = app_sub.add_parser(
        "from-prompt", help="scaffold an app from a plain-English app idea"
    )
    _add_scaffold_arguments(a_prompt, "prompt")


def _add_scaffold_arguments(parser, positional: str) -> None:
    parser.add_argument(positional)
    parser.add_argument("--out", help="output directory; defaults to app slug")
    parser.add_argument("--name", help="app slug override")
    parser.add_argument(
        "--stack", default="nextjs-fastapi-postgres", choices=sorted(_APP_STACK_CHOICES)
    )
    parser.add_argument(
        "--purpose",
        default="auto",
        help="auto, developer, healthcare, fintech, marketplace, saas",
    )
    parser.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch app scaffolding without granting merge, release, or deploy authority."""
    from .app_builder import STACKS, app_from_prd, app_from_prompt

    if a.app_cmd == "stacks":
        print(json.dumps({"stacks": STACKS}, indent=2))
        return 0
    if a.app_cmd == "from-prd":
        result = app_from_prd(
            Path(a.prd),
            out_dir=Path(a.out) if a.out else None,
            name=a.name,
            stack=a.stack,
            purpose=a.purpose,
        )
    else:
        result = app_from_prompt(
            a.prompt,
            out_dir=Path(a.out) if a.out else None,
            name=a.name,
            stack=a.stack,
            purpose=a.purpose,
        )
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"app scaffolded: {result['out_dir']}")
        print(f"files         : {len(result['files'])}")
        print("next:")
        for command in result["next_commands"]:
            print(f"  {command}")
    return 0

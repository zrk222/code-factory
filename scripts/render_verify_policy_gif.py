"""Render the README policy-proof GIF from real example command receipts."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "verify-policy" / "python"
OUT = ROOT / "docs" / "assets" / "verify-policy.gif"
WIDTH, HEIGHT = 1200, 720


def run(challenge: str) -> dict:
    command = [
        sys.executable,
        "-m",
        "factoryline.cli",
        "verify-policy",
        "--root",
        ".",
        "--challenge",
        challenge,
    ]
    completed = subprocess.run(command, cwd=EXAMPLE, capture_output=True, text=True, check=False)
    return {"command": "factory verify-policy --root . --challenge " + challenge, "exit": completed.returncode, "receipt": json.loads(completed.stdout)}


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for candidate in (
        Path("C:/Windows/Fonts/CascadiaMono.ttf"),
        Path("C:/Windows/Fonts/consola.ttf"),
    ):
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def frame(lines: list[tuple[str, str]]) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), "#20222d")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((40, 40, WIDTH - 40, HEIGHT - 40), radius=16, fill="#282a36", outline="#6272a4", width=2)
    draw.rounded_rectangle((40, 40, WIDTH - 40, 94), radius=16, fill="#343746")
    draw.text((76, 58), "factoryline / policy mutation proof", fill="#f8f8f2", font=font(22))
    y = 132
    for kind, text in lines:
        color = {"command": "#8be9fd", "verified": "#50fa7b", "hollow": "#ff5555", "detail": "#f8f8f2"}[kind]
        draw.text((76, y), text, fill=color, font=font(24 if kind != "detail" else 21))
        y += 52
    return image


def main() -> int:
    verified = run("policy.challenge.json")
    hollow = run("policy.challenge.hollow.json")
    if verified["exit"] != 0 or verified["receipt"]["status"] != "VERIFIED":
        raise RuntimeError("verified policy example did not pass")
    if hollow["exit"] == 0 or hollow["receipt"]["status"] != "HOLLOW_POLICY":
        raise RuntimeError("hollow policy example did not fail")
    frames = [
        frame([("command", "> " + verified["command"])]),
        frame([
            ("command", "> " + verified["command"]),
            ("verified", "VERIFIED  -  every mutation was caught"),
            ("detail", f"baseline: exit {verified['receipt']['baseline_returncode']}"),
            ("detail", f"mutations caught: {len(verified['receipt']['mutations'])}/{len(verified['receipt']['mutations'])}"),
        ]),
        frame([("command", "> " + hollow["command"])]),
        frame([
            ("command", "> " + hollow["command"]),
            ("hollow", "HOLLOW_POLICY  -  evaluator accepted broken policy"),
            ("detail", f"mutations that survived: {len(hollow['receipt']['hollow'])}"),
            ("detail", "A policy file is not proof until its evaluator can fail."),
        ]),
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=[1100, 2800, 1100, 3300], loop=0, optimize=True)
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

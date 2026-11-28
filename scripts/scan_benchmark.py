"""Pinned, receipted timing for `factory scan --static-only` (plan milestone M0).

usage: python scripts/scan_benchmark.py CORPUS_DIR OUT_JSON [--runs N] [--workers N]

Every run must produce byte-identical scan JSON. The receipt records the corpus
digest, line count, host shape, worker count, each wall time, the spread and
the output digest, so a timing claim can be checked rather than quoted.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


def corpus_digest(root):
    files = sorted(p for p in Path(root).rglob("*.py") if p.is_file())
    digest, lines = hashlib.sha256(), 0
    for path in files:
        data = path.read_bytes()
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(data).digest())
        lines += data.count(b"\n")
    return digest.hexdigest(), len(files), lines


def timed_scan(root, workers):
    env = {**os.environ, "FACTORY_SCAN_WORKERS": str(workers)}
    code = "import sys; from factoryline.cli import main; sys.argv=['factory','scan','--root',sys.argv[1],'--static-only','--json']; main()"
    start = time.perf_counter()
    run = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, env=env)
    elapsed = time.perf_counter() - start
    if run.returncode != 0:
        raise SystemExit(f"scan failed with exit {run.returncode}: {run.stderr.decode()[-400:]}")
    return elapsed, hashlib.sha256(run.stdout).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus")
    parser.add_argument("out")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--workers", type=int, default=0, help="0 = scanner default")
    args = parser.parse_args(argv)
    corpus_sha256, files, lines = corpus_digest(args.corpus)
    results = [timed_scan(args.corpus, args.workers) for _ in range(max(1, args.runs))]
    times = sorted(elapsed for elapsed, _ in results)
    outputs = {digest for _, digest in results}
    median = times[len(times) // 2]
    spread = (times[-1] - times[0]) / median if median else 0.0
    receipt = {
        "schema": "factory.scan-benchmark.v1",
        "corpus_sha256": corpus_sha256, "python_files": files, "lines": lines,
        "host": {"cpus": os.cpu_count(), "system": platform.system(), "python": platform.python_version()},
        "workers": args.workers, "runs_seconds": [round(t, 3) for t in times],
        "median_seconds": round(median, 3), "spread": round(spread, 4),
        "lines_per_second": round(lines / median) if median else None,
        "output_sha256": sorted(outputs),
        "stable_output": len(outputs) == 1, "stable_timing": spread <= 0.10,
    }
    Path(args.out).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({k: receipt[k] for k in ("median_seconds", "spread", "stable_output", "stable_timing")}))
    return 0 if receipt["stable_output"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

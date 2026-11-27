"""Verify every arm G run pin before any reserve case is opened. Exit 0 only if all pins match.

usage: verify_lock.py REPO_ROOT HARNESS_SCRIPTS_DIR OPENGREP_BINARY
"""
import json, sys, hashlib, os
root, harness, engine = sys.argv[1:4]
sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()
lock = json.load(open(os.path.join(root, 'docs/evidence/precision-tier-prereg-20261127/run-lock.json')))
checks = [(f, os.path.join(root, f), h) for f, h in lock['repo_files'].items()]
checks += [(f, os.path.join(harness, f), h) for f, h in lock['scorer']['files'].items()]
ok = True
for name, path, want in checks:
    got = sha(path) if os.path.exists(path) else 'missing'
    print(f"{'PASS' if got == want else 'FAIL'} {name}"); ok &= got == want
eng = sha(engine)
print(f"{'PASS' if eng in lock['engine']['sha256'].values() else 'FAIL'} engine {eng[:12]}"); ok &= eng in lock['engine']['sha256'].values()
print('LOCK VERIFIED' if ok else 'LOCK FAILED: do not open any reserve case'); sys.exit(0 if ok else 1)

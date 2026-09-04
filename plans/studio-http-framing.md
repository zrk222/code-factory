# Plan: Studio HTTP framing

Spec: specs/studio-http-framing.md
Architect verdict: PASS

- [x] T1 | slice=factoryline | files=factoryline/studio.py,tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Close early-rejected POST connections explicitly and prove the next request reconnects cleanly.

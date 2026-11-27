"""Blinded label packet for held-out precision (factory.label-packet.v1 + context supplement).

usage: build_packet.py OUTDIR SEED LABEL=SCORE_JSON:WORKDIR ...
Union of each arm's old-side alerts. Items show repository, file, line, span, claimed weakness and code
context only: no advisory id, rule id, arm or fix information. The key maps items back.
"""
import json, sys, os, hashlib, random, re
out, seed, arms = sys.argv[1], sys.argv[2], [a.split('=', 1) for a in sys.argv[3:]]
WEAKNESS = [('shell-command|command-injection', 'OS command injection'), ('sql', 'SQL injection'),
            ('path|archive|tarfile|zip', 'Path traversal'), ('html|xss|innerhtml|template', 'XSS / HTML injection'),
            ('deserializ', 'Unsafe deserialization'), ('tls|hostname-verification|certificate', 'Disabled TLS / certificate verification'),
            ('inclusion', 'File inclusion'), ('code-injection|eval', 'Code injection')]
def weakness(rule):
    return next((w for pat, w in WEAKNESS if re.search(pat, rule)), rule.split('.', 1)[-1])
IMPORT = re.compile(r'^\s*(import\b|from\s+\S+\s+import\b|require\b|use\s|using\s|include|#include|package\s)')
alerts = {}
for label, spec in arms:
    score, workdir = spec.split(':', 1)
    for case in json.load(open(score))['cases']:
        cap = (case.get('captures') or {}).get('old') or {}
        if not cap.get('sarif'): continue
        root = os.path.join(workdir, cap['source_root'])
        hunks = {h.get('path'): h for h in (case.get('hunk_findings') or []) if isinstance(h, dict)}
        for run in json.load(open(os.path.join(workdir, cap['sarif']['path']))).get('runs', []):
            for res in run.get('results', []):
                loc = res['locations'][0]['physicalLocation']; reg = loc['region']
                rule = res['ruleId'].split('pins.')[-1]
                key = (case['ghsa'], loc['artifactLocation']['uri'], reg['startLine'], rule)
                a = alerts.setdefault(key, {'arms': set(), 'repository': case['repository'], 'root': root,
                    'span': [reg.get('startColumn'), reg.get('endLine', reg['startLine']) - reg['startLine'], reg.get('endColumn')]})
                a['arms'].add(label)
items, key = [], {}
for (ghsa, path, line, rule), a in alerts.items():
    raw = open(os.path.join(a['root'], path), 'rb').read(); lines = raw.decode('utf-8', 'replace').split('\n')
    fmt = lambda lo, hi: '\n'.join(f"{i + 1:5d}{'>' if i + 1 == line else ' '} {lines[i]}" for i in range(max(0, lo), min(len(lines), hi)))
    iid = hashlib.sha256(f'{ghsa}|{path}|{line}|{rule}'.encode()).hexdigest()[:12]
    items.append({'item': iid, 'repository': a['repository'], 'file': path, 'line': line, 'span': a['span'],
                  'claimed_weakness': weakness(rule), 'context': fmt(line - 6, line + 5),
                  'context_wide': fmt(line - 41, line + 40),
                  'file_header_imports': '\n'.join(f'{i + 1:5d}  {l}' for i, l in enumerate(lines[:200]) if IMPORT.match(l))[:2500]})
    key[iid] = {'case': ghsa, 'file': path, 'line': line, 'rule': rule, 'arms': sorted(a['arms']),
                'source_sha256': hashlib.sha256(raw).hexdigest(), 'span': a['span']}
items.sort(key=lambda x: x['item']); random.Random(seed).shuffle(items)
instructions = ("For each item, decide whether the marked line (>) is a real instance of the claimed weakness: attacker- or "
  "user-influenced data can reach it in a realistic deployment of this library or application, with no effective validation in "
  "the shown or implied code. If a span is present, it gives the start column, end-line offset, and end column. Use context_wide "
  "and file_header_imports when the short context is not enough. Answer TP, FP or UNCLEAR, with one sentence of reasoning. Judge "
  "each item on its own; do not look up advisories, fixes, repositories or other labels, and do not use the web.")
packet = {'schema': 'factory.label-packet.v1+context', 'cohort': os.path.basename(out.rstrip('/')), 'seed': seed,
          'instructions': instructions, 'items': items}
os.makedirs(out, exist_ok=True)
pb = json.dumps(packet, indent=1).encode(); open(os.path.join(out, 'packet.json'), 'wb').write(pb)
psha = hashlib.sha256(pb).hexdigest()
json.dump({'packet_sha256': psha, 'key': key}, open(os.path.join(out, 'key.json'), 'w'), indent=1)
by_arm = {l: sum(l in a['arms'] for a in alerts.values()) for l, _ in arms}
print(json.dumps({'items': len(items), 'by_arm': by_arm, 'packet_sha256': psha}))

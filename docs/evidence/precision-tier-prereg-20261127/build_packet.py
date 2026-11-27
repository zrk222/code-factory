"""Blinded label packet built from the recall harness's `review-alerts` export (old side).

usage: build_packet.py OUTDIR SEED RULES_YML ALERTS_JSON=SCORE_JSON [...]
The export already fixes the population: every alert in a scored case's changed files, with its full span,
source digest and fix-hunk flag, checked against the score receipt. Items show repository, file, line, span,
claimed weakness and code context only. The key (bound to the packet digest) maps each item to its case, rule,
rule tier and fix-hunk flag; it stays sealed until labels and triage votes are written.
"""
import json, sys, os, hashlib, random, re
import yaml
out, seed, rules_path, exports = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
rules_bytes = open(rules_path, 'rb').read(); rules_sha = hashlib.sha256(rules_bytes).hexdigest()
TIER = {r['id']: ('lead' if (r.get('metadata') or {}).get('confidence') == 'LOW' else 'finding')
        for r in yaml.safe_load(rules_bytes)['rules']}
WEAKNESS = [('shell-command|command-injection', 'OS command injection'), ('sql', 'SQL injection'),
            ('path|archive|tarfile|zip', 'Path traversal'), ('html|xss|innerhtml|template', 'XSS / HTML injection'),
            ('deserializ', 'Unsafe deserialization'), ('tls|hostname-verification|certificate', 'Disabled TLS / certificate verification'),
            ('inclusion', 'File inclusion'), ('code-injection|eval', 'Code injection')]
IMPORT = re.compile(r'^\s*(import\b|from\s+\S+\s+import\b|require\b|use\s|using\s|include|#include|package\s)')
items, key = [], {}
for export, score in (e.split('=', 1) for e in exports):
    repo = {c['ghsa']: c['repository'] for c in json.load(open(score))['cases']}
    for a in json.load(open(export)):
        if a['rules_sha256'] != rules_sha: sys.exit(f'{export}: alert rules digest differs from {rules_path}')
        raw = open(os.path.join(a['root'], a['path']), 'rb').read()
        if hashlib.sha256(raw).hexdigest() != a['source_sha256']: sys.exit(f"{a['case']} {a['path']}: source digest differs")
        rule, line, lines = a['rule'].split('pins.')[-1], a['line'], raw.decode('utf-8', 'replace').split('\n')
        fmt = lambda lo, hi: '\n'.join(f"{i + 1:5d}{'>' if i + 1 == line else ' '} {lines[i]}" for i in range(max(0, lo), min(len(lines), hi)))
        iid = hashlib.sha256(json.dumps([a['case'], a['path'], line, rule, a.get('span')]).encode()).hexdigest()[:12]
        if iid in key: sys.exit(f'duplicate alert identity {iid}')
        items.append({'item': iid, 'repository': repo[a['case']], 'file': a['path'], 'line': line,
                      'span': a.get('span'), 'claimed_weakness': next((w for p, w in WEAKNESS if re.search(p, rule)), rule.split('.', 1)[-1]),
                      'context': fmt(line - 6, line + 5), 'context_wide': fmt(line - 41, line + 40),
                      'file_header_imports': '\n'.join(f'{i + 1:5d}  {l}' for i, l in enumerate(lines[:200]) if IMPORT.match(l))[:2500]})
        key[iid] = {'case': a['case'], 'file': a['path'], 'line': line, 'rule': rule, 'span': a.get('span'), 'tier': TIER[rule],
                    'on_fix_hunk': a['on_fix_hunk'], 'source_sha256': a['source_sha256']}
items.sort(key=lambda x: x['item']); random.Random(seed).shuffle(items)
instructions = ("For each item, decide whether the marked line (>) is a real instance of the claimed weakness: attacker- or "
  "user-influenced data can reach it in a realistic deployment of this library or application, with no effective validation in "
  "the shown or implied code. If a span is present, it gives the start column, end-line offset, and end column. Use context_wide "
  "and file_header_imports when the short context is not enough. Answer TP, FP or UNCLEAR, with one sentence of reasoning. Judge "
  "each item on its own; do not look up advisories, fixes, repositories or other labels, and do not use the web.")
packet = {'schema': 'factory.label-packet.v2', 'cohort': os.path.basename(out.rstrip('/')), 'seed': seed,
          'instructions': instructions, 'items': items}
os.makedirs(out, exist_ok=True)
pb = json.dumps(packet, indent=1).encode(); open(os.path.join(out, 'packet.json'), 'wb').write(pb)
psha = hashlib.sha256(pb).hexdigest()
kb = json.dumps({'packet_sha256': psha, 'rules_sha256': rules_sha, 'key': key}, indent=1).encode()
open(os.path.join(out, 'key.json'), 'wb').write(kb)
print(json.dumps({'items': len(items), 'packet_sha256': psha, 'key_sha256': hashlib.sha256(kb).hexdigest()}))

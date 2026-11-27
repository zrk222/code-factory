"""Tuning-data analysis: does CodeQL corroboration separate TP from FP pattern alerts? (exposed-161 labels only)"""
import json, gzip, glob, os, re, hashlib, collections, math, yaml
W = 3
CWE_FAM = {'cmd': {77, 78, 88}, 'sql': {89, 564, 943}, 'path': {22, 23, 36, 73, 99}, 'xss': {79, 80, 116},
           'deser': {502}, 'tls': {295, 297}, 'incl': {98}, 'code': {94, 95}}
PAT_FAM = [('shell-command|command-injection', 'cmd'), ('sql', 'sql'), ('path|archive|tarfile', 'path'),
           ('html|innerhtml|template', 'xss'), ('deserializ', 'deser'), ('tls|hostname', 'tls'), ('inclusion', 'incl')]
pfam = lambda r: next((f for p, f in PAT_FAM if re.search(p, r)), None)
rules = {r['id']: r for r in yaml.safe_load(open('/home/claude/wt-audit/deploy/deep-adapters/rules/semgrep-pattern-limited.yml'))['rules']}
tier = lambda r: (rules.get(r, {}).get('metadata') or {}).get('confidence', '?')
def codeql_index(ghsa):
    for d in ('/home/claude/report/codeql-exposed/sarif-ramdiag', '/home/claude/report/codeql-exposed/sarif'):
        p = f'{d}/{ghsa}/old.sarif.gz'
        if os.path.exists(p): break
    else: return None
    s = json.loads(gzip.decompress(open(p, 'rb').read())); idx = collections.defaultdict(set)
    for run in s['runs']:
        meta = {}
        for comp in [run['tool']['driver']] + run['tool'].get('extensions', []):
            for r in comp.get('rules', []) or []:
                cwes = {int(m) for t in (r.get('properties', {}).get('tags') or []) for m in re.findall(r'cwe-0*(\d+)', t)}
                meta[r['id']] = {f for f, cs in CWE_FAM.items() if cwes & cs}
        for res in run.get('results', []):
            fams = meta.get(res['ruleId'], set())
            locs = [l['physicalLocation'] for l in res.get('locations', [])]
            for cf in res.get('codeFlows', []):
                for tf in cf.get('threadFlows', []):
                    locs += [x['location']['physicalLocation'] for x in tf.get('locations', []) if 'physicalLocation' in x.get('location', {})]
            for l in locs:
                uri = l.get('artifactLocation', {}).get('uri'); line = l.get('region', {}).get('startLine')
                if uri and line:
                    for f in fams: idx[(uri, f)].add(line)
    return idx
labels = {}
for f in glob.glob('/home/claude/precision/labels/*.json'):
    for r in json.load(open(f))['rows']: labels[(r['case'], r['file'], r['line'], r['rule'])] = (r['final'], r['source_sha256'])
Wd = '/home/claude/report/integrated-validation/exposed/work'
score = json.load(open('/home/claude/report/integrated-validation/exposed/arms/head-a73d398c.score.json'))
tab = collections.defaultdict(collections.Counter); hitcase = collections.Counter(); scanned = 0
for c in score['cases']:
    cap = (c.get('captures') or {}).get('old') or {}
    idx = codeql_index(c['ghsa'])
    if idx is None or not cap.get('sarif'): continue
    scanned += 1; corr_hit = False; med_hit = False
    for run in json.load(open(os.path.join(Wd, cap['sarif']['path']))).get('runs', []):
        for res in run.get('results', []):
            loc = res['locations'][0]['physicalLocation']; rid = res['ruleId'].split('pins.')[-1]
            uri, line = loc['artifactLocation']['uri'], loc['region']['startLine']
            corr = any(abs(x - line) <= W for x in idx.get((uri, pfam(rid)), ()))
            k = (c['ghsa'], uri, line, rid); lab = labels.get(k)
            v = lab[0] if lab and lab[1] == hashlib.sha256(open(os.path.join(Wd, cap['source_root'], uri), 'rb').read()).hexdigest() else 'UNLABELED'
            tab[(tier(rid), corr)][v] += 1
    if c.get('hunk_hit'):
        hf = c['hunk_findings']
        fin = any(tier(h[0].split('pins.')[-1]) in ('MEDIUM', 'HIGH') for h in hf)
        cor = any(tier(h[0].split('pins.')[-1]) == 'LOW' and any(abs(x - h[2]) <= W for x in idx.get((h[1], pfam(h[0].split('pins.')[-1])), ())) for h in hf)
        hitcase['finding (MEDIUM)' if fin else 'LOW corroborated' if cor else 'LOW only (lead)'] += 1
print('exposed cases with a CodeQL old-side scan:', scanned)
for (t, corr), cnt in sorted(tab.items()):
    tp, fp = cnt['TP'], cnt['FP']
    print(f'  {t:6s} corroborated={str(corr):5s} alerts {sum(cnt.values()):4d}  TP {tp:3d} FP {fp:3d} UNC {cnt["UNCLEAR"]:2d}  precision {tp/(tp+fp):.0%}' if tp+fp else f'  {t:6s} corroborated={corr} alerts {sum(cnt.values())} (no labels)')
print('hit cases among scanned:', dict(hitcase))

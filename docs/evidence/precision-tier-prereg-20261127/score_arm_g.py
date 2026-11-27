"""Arm G endpoints (prereg.json arm_G_two_stage_triage), computed once on the reserve; arm F as a secondary.

usage: score_arm_g.py DIR SCORE_JSON          (endpoints)
       score_arm_g.py DIR --stage2 OUT_JSON   (after the Haiku votes: the items Sonnet triages, before any label is read)
DIR: packet.json and key.json (build_packet.py); labels-opus.json and labels-fable.json; adjudication-opus.json and
adjudication-fable.json for the items the two labelers split on; Haiku votes triage-H{a,b,c}-part*.json; Sonnet votes
triage-S{a,b,c}-part*.json for the items with at least 2 verified Haiku votes. SCORE_JSON: the pinned score receipt.
"""
import json, sys, glob, re, os, collections
from scipy.stats import beta
d, score = sys.argv[1], sys.argv[2]
KINDS = {'request', 'cli', 'env', 'file', 'message', 'public_api_param'}
items = {i['item']: i for i in json.load(open(f'{d}/packet.json'))['items']}; key = json.load(open(f'{d}/key.json'))['key']
lines = {i: {int(m) for m in re.findall(r'^\s*(\d+)[> ]', it['context_wide'] + '\n' + it.get('file_header_imports', ''), re.M)} for i, it in items.items()}
def verified(v, i):
    try:
        s, e, k = int(v['source_line']), int(v['entry_line']), int(v['sink_line'])
    except (TypeError, ValueError, KeyError):
        return False
    return v.get('decision') == 'REPORT' and v.get('source_kind') in KINDS and k == items[i]['line'] and s in lines[i] and e in lines[i]
def votes(model):  # a missing verdict counts as SUPPRESS
    runs = [{v['item']: v for f in sorted(glob.glob(f'{d}/triage-{model}{r}-part*.json')) for v in json.load(open(f))['triage']} for r in 'abc']
    return {i: sum(i in run and verified(run[i], i) for run in runs) for i in items}
H = votes('H')
if score == '--stage2':
    packet = json.load(open(f'{d}/packet.json'))
    json.dump({**packet, 'items': [it for it in packet['items'] if H[it['item']] >= 2]}, open(sys.argv[3], 'w'), indent=1)
    sys.exit(print(json.dumps({'stage2_items': sum(v >= 2 for v in H.values()), 'items': len(items)})))
S = votes('S')
read = lambda name, field='labels': {l['item']: l['verdict'] for l in json.load(open(f'{d}/{name}'))[field]} if os.path.exists(f'{d}/{name}') else {}
lo, lf, ao, af = read('labels-opus.json'), read('labels-fable.json'), read('adjudication-opus.json'), read('adjudication-fable.json')
# Agreement decides; a split goes to one adjudication round (both models see both rationales); a split that remains is UNCLEAR.
final = {i: lo[i] if lo[i] == lf[i] else (ao[i] if ao.get(i) and ao.get(i) == af.get(i) else 'UNCLEAR') for i in items}
G = {i for i in items if H[i] >= 2 and S[i] == 3}
lb = lambda k, n: float(beta.ppf(0.05, k, n - k + 1)) if k else 0.0
ub = lambda k, n: float(beta.ppf(0.95, k + 1, n - k)) if k < n else 1.0
def read_out(ids, unclear_fp=False):
    tp = sum(final[i] == 'TP' for i in ids); fp = sum(final[i] == 'FP' or (unclear_fp and final[i] == 'UNCLEAR') for i in ids)
    return tp, fp, (tp / (tp + fp) if tp + fp else None)
def verdict(ids):
    tp, fp, p = read_out(ids); n = tp + fp
    by = collections.defaultdict(list)
    for i in ids:
        if final[i] != 'UNCLEAR': by[key[i]['case']].append(final[i] == 'TP')
    ctp = sum(sum(v) > len(v) / 2 for v in by.values()); cn = len(by)  # one outcome per case; ties are FP
    repo_tp = collections.Counter(items[i]['repository'] for i in ids if final[i] == 'TP')
    top = repo_tp.most_common(1)[0][0] if repo_tp else None
    drop = read_out([i for i in ids if items[i]['repository'] != top])[2]
    ufp = read_out(ids, True)[2]
    robust = cn >= 5 and drop is not None and drop >= 0.49 and ufp is not None and ufp >= 0.49
    def level(cut, bound):
        return n >= 5 and p >= cut and lb(tp, n) > bound and ctp / cn >= cut and lb(ctp, cn) > bound and robust
    return {'findings': len(ids), 'decided': n, 'TP': tp, 'FP': fp, 'UNCLEAR': len(ids) - n, 'precision': p,
            'cp_lb95_one_sided': lb(tp, n) if n else None, 'cp_ub95_one_sided': ub(tp, n) if n else None,
            'case_level': {'cases': cn, 'tp_cases': ctp, 'cp_lb95': lb(ctp, cn) if cn else None},
            'drop_top_tp_repository': {'repository_dropped': bool(top), 'precision': drop}, 'unclear_as_fp': ufp,
            'six_x_point': bool(n >= 5 and p >= 0.49), 'eight_x_point': bool(n >= 5 and p >= 0.656),
            'six_x_confirmed': level(0.49, 0.246), 'eight_x_confirmed': level(0.656, 0.328),
            'six_x_strong': bool(n >= 5 and lb(tp, n) >= 0.49 and robust), 'eight_x_strong': bool(n >= 5 and lb(tp, n) >= 0.656 and robust),
            'not_met': bool(n >= 5 and ub(tp, n) < 0.49), 'inconclusive_small_n': n < 5}
hit = {key[i]['case'] for i in items if key[i]['on_fix_hunk']}
kept = {key[i]['case'] for i in G if key[i]['on_fix_hunk']}
scored = json.load(open(score))['summary']['scored']
print(json.dumps({'arm_G': verdict(G),
                  'recall': {'scored_cases': scored, 'hit_cases_all_alerts': len(hit), 'hit_cases_kept_as_findings': len(kept)},
                  'secondary': {'arm_F_haiku_3of3': verdict({i for i in items if H[i] == 3}),
                                'haiku_3of3_sonnet_2of3': verdict({i for i in items if H[i] == 3 and S[i] >= 2}),
                                'overall_precision_all_alerts': read_out(list(items))[2],
                                'tiers': {t: read_out([i for i in items if key[i]['tier'] == t])[2] for t in ('finding', 'lead')}},
                  'label_agreement': {'agree': sum(lo[i] == lf[i] for i in items), 'items': len(items)}}, indent=1))

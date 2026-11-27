"""Adjudicate blinded labels and score per-arm precision.

usage: score_labels.py DIR judge-packet   -> DIR/judge-packet.json (disagreements between labels-arm1/arm2)
       score_labels.py DIR final          -> DIR/precision.json (needs judge.json when there are disagreements)
Labels files: DIR/labels-arm1.json, DIR/labels-arm2.json, each {"labels": [{"item","verdict","reason"}]}.
"""
import json, sys, os, math, hashlib, collections
d, mode = sys.argv[1], sys.argv[2]
packet = json.load(open(f'{d}/packet.json')); key = json.load(open(f'{d}/key.json'))['key']
items = {i['item']: i for i in packet['items']}
def labels(n):
    out = {l['item']: l for l in json.load(open(f'{d}/labels-arm{n}.json'))['labels']}
    assert set(out) == set(items), f'arm{n} labels do not cover the packet exactly'
    assert all(l['verdict'] in ('TP', 'FP', 'UNCLEAR') for l in out.values())
    return out
a1, a2 = labels(1), labels(2)
dis = [i for i in items if a1[i]['verdict'] != a2[i]['verdict']]
if mode == 'judge-packet':
    jp = {'schema': 'factory.judge-packet.v2', 'packet_sha256': hashlib.sha256(open(f'{d}/packet.json', 'rb').read()).hexdigest(),
          'instructions': packet['instructions'] + ' Two independent reviewers disagreed on each item below; their verdicts and reasons '
          'are shown. Decide TP, FP or UNCLEAR yourself from the code, with one sentence of reasoning.',
          'disagreements': [{**items[i], 'reviewer_1': {k: a1[i][k] for k in ('verdict', 'reason')},
                             'reviewer_2': {k: a2[i][k] for k in ('verdict', 'reason')}} for i in dis]}
    json.dump(jp, open(f'{d}/judge-packet.json', 'w'), indent=1)
    print(json.dumps({'items': len(items), 'agreed': len(items) - len(dis), 'disagreements': len(dis)})); sys.exit()
judge = {v['item']: v['verdict'] for v in json.load(open(f'{d}/judge.json'))['verdicts']} if dis else {}
assert set(judge) == set(dis), 'judge verdicts must cover exactly the disagreements'
final = {i: (a1[i]['verdict'] if i not in dis else judge[i]) for i in items}
def wilson(k, n, z=1.96):
    if not n: return None
    p = k / n; den = 1 + z * z / n; c = (p + z * z / (2 * n)) / den; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(c - h, 4), round(c + h, 4)]
arms = sorted({a for k in key.values() for a in k['arms']})
res = {'packet_sha256': hashlib.sha256(open(f'{d}/packet.json', 'rb').read()).hexdigest(), 'items': len(items),
       'agreed': len(items) - len(dis), 'judged': len(dis), 'final_counts': dict(collections.Counter(final.values())), 'arms': {}}
for arm in arms:
    c = collections.Counter(final[i] for i in items if arm in key[i]['arms'])
    tp, fp = c['TP'], c['FP']
    res['arms'][arm] = {'alerts': sum(c.values()), **{k: c[k] for k in ('TP', 'FP', 'UNCLEAR')},
                        'precision': round(tp / (tp + fp), 4) if tp + fp else None, 'wilson95': wilson(tp, tp + fp)}
if len(arms) == 2:
    x, y = arms
    for a, b in ((x, y), (y, x)):
        only = collections.Counter(final[i] for i in items if a in key[i]['arms'] and b not in key[i]['arms'])
        res[f'only_{a}'] = dict(only)
json.dump(res, open(f'{d}/precision.json', 'w'), indent=1); print(json.dumps(res, indent=1))

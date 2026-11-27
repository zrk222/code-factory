"""Adjudication packet for the items the two reserve labelers split on (labels stay blind to triage and arms).

usage: adjudication_packet.py DIR   (reads packet.json, labels-opus.json, labels-fable.json; writes adjudication-packet.json)
"""
import json, sys
d = sys.argv[1]
items = {i['item']: i for i in json.load(open(f'{d}/packet.json'))['items']}
lab = {m: {l['item']: l for l in json.load(open(f'{d}/labels-{m}.json'))['labels']} for m in ('opus', 'fable')}
split = sorted(i for i in items if lab['opus'][i]['verdict'] != lab['fable'][i]['verdict'])
packet = {'instructions': json.load(open(f'{d}/packet.json'))['instructions'], 'disagreements': [
    {**items[i], 'reviewer_a': {k: lab['opus'][i][k] for k in ('verdict', 'reason')},
     'reviewer_b': {k: lab['fable'][i][k] for k in ('verdict', 'reason')}} for i in split]}
json.dump(packet, open(f'{d}/adjudication-packet.json', 'w'), indent=1)
print(json.dumps({'split': len(split), 'items': len(items)}))

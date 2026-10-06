"""Pick the model's two thresholds on the validation sets, with the rules in the loop.

    .venv/bin/python ml/sms/thresholds.py <rules-dump.tsv>

The dump is written by MessageModelTest ("writes the rules dump", to
android/build/message-rules-dump.tsv): for every message of the held-out set,
the blind sets and the Kotlin dev corpora, the rules' verdict, whether a
legitimate shape excluded it, whether every link and number in it is
official, and the ingredients the integration may use. Python cannot run the
rules, so they come from the JVM; the model's probability is computed here
from the exported assets (message_model.bin + .json), as the phone does.

The integration (MessageAnalyzer.withModel) only adds, never removes:
 - the rules' "dangerous" stays; a legitimate shape (login code, payment
   alert…), a message whose links and numbers are all official, and one of
   fewer than min_words words are never touched;
 - p ≥ T_DANGER and an ingredient → dangerous;
 - p ≥ T_CAUTION → at least caution.

Hard constraints: no false alarm on any legitimate list of the Kotlin dev
corpora or on the held-out set; at most 1% of the legitimate rows of blind
b+c+d flagged in all (rules and model together). Among the pairs that meet
them, the one with the most blind scams flagged, then the most dangerous —
printed twice: as is, and with a MARGIN between each threshold and the
highest score of a legitimate message it could flag (the pair shipped; see
docs/EVALUATION_2026-10.md §3.14 for why).
"""

from __future__ import annotations

import json
import math
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402
import features as F  # noqa: E402

BLIND = ('blind_b', 'blind_c', 'blind_d')
MARGIN = 0.05
GRID = (0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.925, 0.95, 0.96, 0.97, 0.98, 0.99)


def load_model():
    meta = json.loads((D.MODULE / 'main' / 'assets' / 'message_model.json').read_text(encoding='utf-8'))
    raw = (D.MODULE / 'main' / 'assets' / meta['weights']['file']).read_bytes()
    assert raw[:4] == b'CWSM'
    _, dim = struct.unpack('<II', raw[4:12])
    weights = np.frombuffer(raw[12:], dtype='<f2').astype(np.float64)
    assert len(weights) == dim
    cfg = F.Config.from_json(meta['normaliser'])
    h = meta['hash']

    def prob(text: str) -> float:
        z = meta['bias']
        for b, v in F.vector(text, cfg, dim, h['char_weight'], h['word_weight'], h['char_floor'], h['word_floor']).items():
            z += v * weights[b]
        return 1.0 / (1.0 + math.exp(-z))

    return prob, meta, cfg


def unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            out.append({'n': '\n', 't': '\t', 'r': '\r', '\\': '\\'}[s[i + 1]])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def load_dump(path: str, prob, cfg):
    rows = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        group, label, family, verdict, shape, official, ingredients, text = line.split('\t')
        text = unescape(text)
        rows.append({'group': group, 'scam': label == 'scam', 'family': family, 'verdict': verdict,
                     'shape': shape == 'true', 'official': official == 'true',
                     'ingredients': set(filter(None, ingredients.split(','))),
                     'words': F.word_count(text, cfg), 'text': text, 'p': prob(text)})
    return rows


def combined(r, t_caution, t_danger, min_words, ingredients=None) -> str:
    """The verdict on the phone: MessageAnalyzer.withModel, in Python."""
    v = r['verdict']
    if v == 'dangerous' or r['shape'] or r['official'] or r['words'] < min_words:
        return v
    found = r['ingredients'] if ingredients is None else r['ingredients'] & set(ingredients)
    if r['p'] >= t_danger and found:
        return 'dangerous'
    if r['p'] >= t_caution:
        return 'caution'
    return v


def table(rows, t_caution, t_danger, min_words, ingredients=None):
    out = {}
    for g in sorted({r['group'] for r in rows}):
        rs = [r for r in rows if r['group'] == g]
        v = [combined(r, t_caution, t_danger, min_words, ingredients) for r in rs]
        legit = [x for x, r in zip(v, rs) if not r['scam']]
        scam = [x for x, r in zip(v, rs) if r['scam']]
        out[g] = {'legit': len(legit), 'false_alarms': sum(x != 'no_signals' for x in legit),
                  'scam': len(scam), 'flagged': sum(x != 'no_signals' for x in scam),
                  'dangerous': sum(x == 'dangerous' for x in scam)}
    return out


def feasible(t, blind_legit_total) -> bool:
    for g, m in t.items():
        if (g.startswith('corpus') or g == 'heldout') and m['false_alarms']:
            return False
    return sum(t[g]['false_alarms'] for g in BLIND) <= math.floor(0.01 * blind_legit_total)


def fmt(t) -> str:
    return '  '.join(f"{g.replace('blind_', '')}: FA {m['false_alarms']}/{m['legit']} "
                     f"flag {m['flagged']}/{m['scam']} dang {m['dangerous']}"
                     for g, m in t.items() if g in BLIND + ('heldout',))


def corpus_fa(t) -> int:
    return sum(m['false_alarms'] for g, m in t.items() if g.startswith('corpus'))


def main():
    prob, meta, cfg = load_model()
    min_words = meta['min_words']
    rows = load_dump(sys.argv[1], prob, cfg)
    blind_legit = sum(1 for r in rows if r['group'] in BLIND and not r['scam'])
    print(f"rows {len(rows)}; blind legit {blind_legit} (1% = {math.floor(0.01 * blind_legit)}); min_words {min_words}")
    print('rules only:', fmt(table(rows, 2, 2, min_words)), '| corpora FA', corpus_fa(table(rows, 2, 2, min_words)))
    best = None
    print('\nT_caution T_danger | per set | corpora FA | feasible')
    for tc in GRID:
        for td in GRID:
            t = table(rows, tc, td, min_words)
            ok = feasible(t, blind_legit)
            flagged = sum(t[g]['flagged'] for g in BLIND)
            dangerous = sum(t[g]['dangerous'] for g in BLIND)
            print(f'{tc:<6} {td:<6} | {fmt(t)} | corpora FA {corpus_fa(t)} | {"ok" if ok else "-"}')
            if ok and (best is None or (flagged, dangerous, tc, td) > best[0]):
                best = ((flagged, dangerous, tc, td), tc, td)
    _, tc, td = best
    print(f'\nmost recall within the constraints: T_caution {tc}, T_danger {td}:', fmt(table(rows, tc, td, min_words)))
    # The same, with a margin: no legitimate message the model may touch scores within MARGIN
    # below a threshold that would flag it. The 1% budget is left for unseen messages.
    touchable = [r for r in rows if not r['scam'] and r['verdict'] != 'dangerous' and not r['shape']
                 and not r['official'] and r['words'] >= min_words]
    top_any = max(r['p'] for r in touchable)
    top_ingredient = max(r['p'] for r in touchable if r['ingredients'])
    safe = None
    for tc in GRID:
        for td in GRID:
            if tc < top_any + MARGIN or td < top_ingredient + MARGIN:
                continue
            t = table(rows, tc, td, min_words)
            if not feasible(t, blind_legit):
                continue
            key = (sum(t[g]['flagged'] for g in BLIND), sum(t[g]['dangerous'] for g in BLIND), tc, td)
            if safe is None or key > safe[0]:
                safe = (key, tc, td)
    _, tc, td = safe
    print(f'with a {MARGIN} margin (top legit p {top_any:.3f}, with an ingredient {top_ingredient:.3f}): '
          f'T_caution {tc}, T_danger {td}:', fmt(table(rows, tc, td, min_words)))
    print('\nlegit rows at p ≥ 0.5 (rules verdict; gated = shape/official/short):')
    for r in sorted((r for r in rows if not r['scam'] and r['p'] >= 0.5), key=lambda r: -r['p']):
        gated = r['shape'] or r['official'] or r['words'] < min_words
        print(f"  {r['group']} p={r['p']:.3f} {r['verdict']} gated={gated} {sorted(r['ingredients'])}: {r['text'][:150]}")


if __name__ == '__main__':
    main()

"""Train, check and export the on-device SMS text model.

    .venv/bin/python ml/sms/train.py            # cross-author check, final fit, export
    .venv/bin/python ml/sms/train.py --no-export  # numbers only

Logistic regression over hashed binary features (features.py): char n-grams
2..5 of every word and word unigrams/bigrams, each block at unit norm.
Deterministic: liblinear with a fixed seed, no shuffling, sorted inputs.

Writes (unless --no-export):
 - mobile/.../assets/message_model.bin   float16 weight table
 - mobile/.../assets/message_model.json  the normaliser's lists, the hash
   layout, the bias, the thresholds, data hashes and metrics
 - mobile/.../test/resources/message_model_parity.tsv  ~300 texts with the
   probability this file computes; MessageModelTest asserts the Kotlin twin
   agrees to 1e-4.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import struct
import sys
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402
import features as F  # noqa: E402

SEED = 20261006
DIM = 1 << 18
NGRAMS = (2, 5)
CHAR_WEIGHT = 1.0
WORD_WEIGHT = 2.0
# A block with fewer features is normalised as if it had this many (features.vector).
CHAR_FLOOR = 1
WORD_FLOOR = 1
# Fewer words than this and the model abstains: one or two words are no evidence ("срочно").
MIN_WORDS = 5
C = 30.0
MODEL_VERSION = 1

# Chosen on the validation sets with ml/sms/thresholds.py (docs/EVALUATION_2026-10.md §3.14):
# p ≥ T_CAUTION on a message the rules let through → caution, reason text_resembles_scam;
# p ≥ T_DANGER with one of the rules' ingredients → dangerous. The pair with the most blind
# scams flagged among those that keep a 0.05 margin above every legitimate validation score
# they could flag (0.844 any, 0.715 with an ingredient); the bare maximum (0.75/0.75) spends
# the false-alarm budget on the validation sets themselves.
T_CAUTION = 0.90
T_DANGER = 0.80

ASSETS = D.MODULE / 'main' / 'assets'
MODEL_BIN = ASSETS / 'message_model.bin'
MODEL_JSON = ASSETS / 'message_model.json'
PARITY = D.TEST_RES / 'message_model_parity.tsv'
MAGIC = b'CWSM'


class Model:
    def __init__(self, weights: np.ndarray, bias: float, cfg: F.Config):
        self.weights = weights.astype(np.float16).astype(np.float64)  # as shipped
        self.bias = float(bias)
        self.cfg = cfg

    def logit(self, text: str) -> float:
        z = self.bias
        for b, v in F.vector(text, self.cfg, DIM, CHAR_WEIGHT, WORD_WEIGHT, CHAR_FLOOR, WORD_FLOOR).items():
            z += v * self.weights[b]
        return z

    def prob(self, text: str) -> float:
        return 1.0 / (1.0 + math.exp(-self.logit(text)))


def matrix(rows, cfg):
    indptr, indices, values = [0], [], []
    for r in rows:
        v = F.vector(r.text, cfg, DIM, CHAR_WEIGHT, WORD_WEIGHT, CHAR_FLOOR, WORD_FLOOR)
        for b in sorted(v):
            indices.append(b)
            values.append(v[b])
        indptr.append(len(indices))
    return sparse.csr_matrix((values, indices, indptr), shape=(len(rows), DIM))


def fit(X, y, c=C):
    clf = LogisticRegression(C=c, solver='liblinear', class_weight='balanced', random_state=SEED, max_iter=1000)
    clf.fit(X, y)
    return clf.coef_[0], clf.intercept_[0]


def scores(X, w, b):
    w16 = w.astype(np.float16).astype(np.float64)
    z = X @ w16 + b
    return 1.0 / (1.0 + np.exp(-z))


def summary(y, p) -> dict:
    """AUC, accuracy at 0.5, and scam recall at the thresholds that allow 0 / 1% / 5% false alarms."""
    y = np.asarray(y)
    p = np.asarray(p)
    legit = np.sort(p[y == 0])[::-1]
    out = {'n': int(len(y)), 'auc': round(float(roc_auc_score(y, p)), 4),
           'acc@0.5': round(float(((p >= 0.5) == (y == 1)).mean()), 4)}
    for fpr in (0.0, 0.01, 0.05):
        k = int(math.floor(fpr * len(legit)))
        t = legit[k] if k < len(legit) else 0.0  # strictly above the (k+1)-th highest legit score
        out[f'recall@fpr{fpr:g}'] = round(float((p[y == 1] > t).mean()), 4)
    return out


def cross_author(rows, cfg, c=C, with_corpora=True):
    """Train on two authors (and the Kotlin corpora), test on the third."""
    out = {}
    for held in ('a', 'b', 'c'):
        tr = [r for r in rows if r.source != held and (with_corpora or r.source != 'k')]
        te = [r for r in rows if r.source == held]
        w, b = fit(matrix(tr, cfg), [r.label for r in tr], c)
        out[held] = summary([r.label for r in te], scores(matrix(te, cfg), w, b))
    return out


def length_check(rows, p):
    """Mean score by length tercile within each label: a length bias shows as a slope."""
    out = {}
    for label in (0, 1):
        idx = [i for i, r in enumerate(rows) if r.label == label]
        idx.sort(key=lambda i: len(rows[i].text))
        thirds = np.array_split(np.array(idx), 3)
        out['scam' if label else 'legit'] = [
            {'chars': f'{len(rows[t[0]].text)}-{len(rows[t[-1]].text)}', 'mean_p': round(float(np.mean(p[t])), 4)}
            for t in thirds if len(t)
        ]
    return out


def parity_texts(train_rows, validation) -> list[str]:
    rnd = random.Random(SEED)
    texts = [r.text for r in rnd.sample(train_rows, 150)]
    for rows in validation.values():
        texts += [r.text for r in rnd.sample(rows, 25)]
    texts += [
        '', ' ', '!!!', 'Привет', 'ok', '0', '+7 900 000-00-47', '2200 **** **** 1234', '9** ***-**-NN',
        'Гoсуслуги: ваш аккаунт взлoман https://185.176.43.12/gosuslugi пиши @evil_bot или a@b.ru, т.е. г.Москва',
        'Ozon: заказ готов ozon.ru/my, Telegram t.me/x, ссылка clck.ru/3FgH7k, файл vozvrat.apk, сайт evil.top/x.apk?y=1',
        'госуслуги.рф сбербанк.com сбербанк.com/x HTTPS://WWW.SBER-BONUS.ONLINE/LOGIN?id=1#a mir-kartа-help.xyz',
        'ma eto ya, pishu s chuzhogo telefona, popal v avariyu, nuzhno 40 tys srochno, shchas perevedi',
        'Vash kod: 1234. Nikomu ne soobshchayte. yandex.ru',
        'ЁЛКА Ёж ЀЍЎЏ Ђ ђ İstanbul ß Straße ﬁ ǅ Σίσυφος ΣΑΣ',
        'Гос​услуги зап­рос﻿ — 500₽, $20, €5, £1, 70к, 3k',
        "don't can’t l'amour den'gi",
        '😀🔥 эмодзи 👍🏽 и 𝔘𝔫𝔦𝔠𝔬𝔡𝔢',
        'a.b.c.d 1.500 руб 10.30 24.09.2026 т.д. ул.Ленина Яндекс.Маркет app.Подробнее update.zip foto_party.apk',
        '((("ссылка: evil-site.top/path")))... «sber.ru»',
        'Сбербанк: ' + 'очень длинное сообщение ' * 300,
    ]
    out, seen = [], set()
    for t in texts:
        if t not in seen and '\t' not in t and '\n' not in t and '\r' not in t:
            seen.add(t)
            out.append(t)
    return out


def export(model: Model, w, meta: dict, parity: list[str]):
    ASSETS.mkdir(parents=True, exist_ok=True)
    with open(MODEL_BIN, 'wb') as f:
        f.write(MAGIC)
        f.write(struct.pack('<II', MODEL_VERSION, DIM))
        f.write(w.astype('<f2').tobytes())
    MODEL_JSON.write_text(json.dumps(meta, ensure_ascii=False, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    lines = ['# MessageModelTest: probability computed by ml/sms/train.py (features.py) for each text.',
             '# Generated; do not edit. Columns: probability<TAB>text']
    lines += [f'{model.prob(t):.10f}\t{t}' for t in parity]
    PARITY.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--no-export', action='store_true')
    ap.add_argument('--no-corpora', action='store_true', help='train on train_a/b/c only')
    ap.add_argument('--C', type=float, default=C)
    ap.add_argument('--grid', action='store_true', help='cross-author AUC for a grid of C')
    args = ap.parse_args()
    with_corpora = not args.no_corpora

    cfg = D.config()
    validation = D.load_validation()
    rows, dropped = D.training_rows(cfg, with_corpora, validation)
    rows.sort(key=lambda r: (r.source, r.label, r.family, r.text))
    print(f'training rows: {len(rows)}; dropped: {len(dropped)}')
    reasons = {}
    for r, why in dropped:
        reasons[(r.source, why)] = reasons.get((r.source, why), 0) + 1
    for k in sorted(reasons):
        print(f'  dropped {k[0]}: {k[1]}: {reasons[k]}')

    if args.grid:
        for c in (0.3, 1, 3, 10, 30, 100):
            ca = cross_author(rows, cfg, c, with_corpora)
            print(f'C={c}: ' + '  '.join(f"{h}: auc {m['auc']} r@1% {m['recall@fpr0.01']}" for h, m in ca.items()))
        return

    ca = cross_author(rows, cfg, args.C, with_corpora)
    print('cross-author (train on the other two' + (' + Kotlin corpora' if with_corpora else '') + '):')
    for held, m in ca.items():
        print(f'  test {held}: {m}')

    X = matrix(rows, cfg)
    y = np.array([r.label for r in rows])
    w, b = fit(X, y, args.C)
    model = Model(w, b, cfg)
    train_p = scores(X, w, b)
    print('train:', summary(y, train_p))
    print('length check (train):', length_check(rows, train_p))
    val = {}
    for name, vrows in validation.items():
        p = scores(matrix(vrows, cfg), w, b)
        val[name] = summary([r.label for r in vrows], p)
        print(f'{name}: {val[name]}')
        print(f'  length check {name}:', length_check(vrows, p))
    corpora_legit = [r for r in D.load_kotlin_corpora() if r.label == 0]
    p = scores(matrix(corpora_legit, cfg), w, b)
    print(f'Kotlin corpora legit ({"trained on" if with_corpora else "unseen"}): max p {p.max():.4f}, '
          f'≥{T_CAUTION}: {(p >= T_CAUTION).sum()}, ≥{T_DANGER}: {(p >= T_DANGER).sum()}')

    if args.no_export:
        return
    meta = {
        'version': MODEL_VERSION,
        'kind': 'logistic regression over hashed features (ml/sms/train.py)',
        'hash': {'dim': DIM, 'function': 'fnv1a32 over UTF-16LE code units, then murmur3 fmix32; bucket = h & (dim-1)',
                 'char_ngrams': list(NGRAMS), 'char_weight': CHAR_WEIGHT, 'word_weight': WORD_WEIGHT,
                 'char_floor': CHAR_FLOOR, 'word_floor': WORD_FLOOR,
                 'prefixes': {'char': 'c', 'word': 'w', 'bigram': 'b'}},
        'max_chars': F.MAX_CHARS,
        'min_words': MIN_WORDS,
        'bias': float(b),
        'weights': {'file': MODEL_BIN.name, 'format': 'CWSM, u32 version, u32 dim, dim x float16 little-endian'},
        'thresholds': {'caution': T_CAUTION, 'dangerous_with_ingredient': T_DANGER},
        'normaliser': cfg.to_json(),
        'training': {
            'C': args.C, 'solver': 'liblinear', 'class_weight': 'balanced', 'seed': SEED,
            'rows': len(rows), 'scam': int(y.sum()), 'legit': int(len(y) - y.sum()),
            'sources': sorted({r.source for r in rows}), 'dropped': len(dropped),
            'dropped_scam_families': sorted(D.DROPPED_SCAM_FAMILIES),
        },
        'data_sha256': D.data_hashes(with_corpora),
        'metrics': {'cross_author': ca, 'validation': val},
    }
    export(model, w, meta, parity_texts(rows, validation))
    print(f'wrote {MODEL_BIN} ({MODEL_BIN.stat().st_size} bytes), {MODEL_JSON}, {PARITY}')


if __name__ == '__main__':
    main()

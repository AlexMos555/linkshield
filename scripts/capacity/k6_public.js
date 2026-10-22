// Public check: MODE=hit (pool of pre-warmed names), miss (a new name every
// request -> stubbed analyzer), allow (top domains, allowlist short-circuit),
// health (GET /health).
import http from 'k6/http';
import { check } from 'k6';

const TARGETS = (__ENV.TARGETS || 'http://api:8080').split(',');
const RATE = parseInt(__ENV.RATE || '50');
const DUR = __ENV.DUR || '30s';
const MODE = __ENV.MODE || 'hit';
// The top 5000 of data/top_10k.json ({name: rank}), most popular first.
const RANKS = JSON.parse(open('../../data/top_10k.json'));
const POPULAR = Object.keys(RANKS).sort((a, b) => RANKS[a] - RANKS[b]).slice(0, 5000);

export const options = {
  scenarios: { pub: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DUR,
    preAllocatedVUs: Math.min(2000, Math.max(50, RATE * 4)), maxVUs: 6000 } },
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const url = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  let path;
  if (MODE === 'health') path = '/health';
  else if (MODE === 'allow') path = `/api/v1/public/check/${POPULAR[Math.floor(Math.random() * 500)]}`;
  else if (MODE === 'hit') path = `/api/v1/public/check/shop${Math.floor(Math.random() * 500)}.capstore.com`;
  else path = `/api/v1/public/check/m${Math.floor(Math.random() * 1e12).toString(36)}.capstore.com`;
  const res = http.get(url + path, { timeout: '15s' });
  check(res, { ok: (r) => r.status === 200 });
}

// DoH GET mix: 88% popular names (Zipf over the top 5000), 2% blocklisted,
// 10% never-seen random names. A/AAAA/HTTPS 45/45/10. Half with EDNS0 padding.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { check } from 'k6';

// The top 5000 of data/top_10k.json ({name: rank}), most popular first.
const RANKS = JSON.parse(open('../../data/top_10k.json'));
const POPULAR = Object.keys(RANKS).sort((a, b) => RANKS[a] - RANKS[b]).slice(0, 5000);
const CUM = (() => { let a = 0; return POPULAR.map((_, i) => (a += 1 / (i + 1))); })();
const TARGETS = (__ENV.TARGETS || 'http://api:8080').split(',');
const RATE = parseInt(__ENV.RATE || '200');
const DUR = __ENV.DUR || '30s';

export const options = {
  scenarios: { doh: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DUR,
    preAllocatedVUs: Math.min(2000, Math.max(50, RATE)), maxVUs: 4000 } },
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
};

function pickPopular() {
  const r = Math.random() * CUM[CUM.length - 1];
  let lo = 0, hi = CUM.length - 1;
  while (lo < hi) { const m = (lo + hi) >> 1; if (CUM[m] < r) lo = m + 1; else hi = m; }
  return POPULAR[lo];
}

function name() {
  const r = Math.random();
  if (r < 0.02) { const i = Math.floor(Math.random() * 650000); return `login-${i}.phish${i % 997}.top`; }
  if (r < 0.12) return `r${Math.floor(Math.random() * 1e12).toString(16)}.example.net`;
  const n = pickPopular();
  return Math.random() < 0.3 ? 'www.' + n : n;
}

function query(qname, qtype, edns, id) {
  const b = [id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, edns ? 1 : 0];
  for (const label of qname.split('.')) { b.push(label.length); for (let i = 0; i < label.length; i++) b.push(label.charCodeAt(i)); }
  b.push(0, qtype >> 8, qtype & 255, 0, 1);
  if (edns) {
    const pad = (128 - ((b.length + 11 + 4) % 128)) % 128;
    b.push(0, 0, 41, 4, 208, 0, 0, 0, 0, (4 + pad) >> 8, (4 + pad) & 255, 0, 12, pad >> 8, pad & 255);
    for (let i = 0; i < pad; i++) b.push(0);
  }
  return new Uint8Array(b).buffer;
}

export default function () {
  const t = Math.random();
  const qtype = t < 0.45 ? 1 : t < 0.9 ? 28 : 65;
  const id = Math.floor(Math.random() * 65536);
  const wire = query(name(), qtype, Math.random() < 0.5, id);
  const url = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  const res = http.get(`${url}/dns-query?dns=${encoding.b64encode(wire, 'rawurl')}`,
    { headers: { accept: 'application/dns-message' }, responseType: 'binary', timeout: '10s' });
  check(res, { ok: (r) => r.status === 200 && r.body && new Uint8Array(r.body)[0] === (id >> 8) });
}

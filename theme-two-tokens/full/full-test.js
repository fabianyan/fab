// Four questions, asked of Chrome rather than of a regex:
//  1. does every one of the 647 tokens still resolve to today's value?
//  2. does one block still move on its own?           <- the product feature
//  3. does a brand change still reach everything?     <- the point of the work
//  4. does row order matter?                          <- the EAV requirement
const puppeteer = require('/home/user/fab/scheme-app/node_modules/puppeteer');
const fs = require('fs');

const rows = JSON.parse(fs.readFileSync('full.eav.json', 'utf8')).rows;
const built = JSON.parse(fs.readFileSync('full.built.json', 'utf8'));
const today = built.today;
const names = Object.keys(today);
const norm = (v) => {
  const s = String(v).trim().toLowerCase().replace(/\s+/g, ' ');
  const m = s.match(/^(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})$/);
  return m ? '#' + m.slice(1).map((n) => (+n).toString(16).padStart(2, '0')).join('') : s;
};
const sheet = (rs) => ':root{' + rs.map((r) => r.attribute + ':' + r.value + ';').join('') + '}';
const read = (p, ns) => p.evaluate((list) => {
  const cs = getComputedStyle(document.documentElement);
  const o = {}; list.forEach((n) => { o[n] = cs.getPropertyValue(n).trim(); }); return o;
}, ns);

(async () => {
  const b = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const p = await b.newPage();
  let ok = true;

  // 1 - value identity
  await p.setContent('<style>' + sheet(rows) + '</style>');
  const base = await read(p, names);
  const bad = names.filter((n) => norm(base[n]) !== norm(today[n]));
  console.log(bad.length ? 'FAIL  ' + bad.length + ' of ' + names.length + ' tokens differ'
                         : 'PASS  all ' + names.length + ' tokens resolve to today\'s value');
  bad.slice(0, 6).forEach((n) => console.log('        ', n, 'want', today[n], 'got', base[n]));
  if (bad.length) ok = false;

  // 2 - per-widget override: one block moves, nothing else does
  const victim = '--v-fg-button';
  const peers = built.blocks.filter((n) => n !== victim);
  const over = rows.map((r) => r.attribute === victim ? Object.assign({}, r, { value: '#ff00ff' }) : r);
  await p.setContent('<style>' + sheet(over) + '</style>');
  const after = await read(p, built.blocks);
  const moved = peers.filter((n) => after[n] !== base[n]);
  const victimMoved = norm(after[victim]) === '#ff00ff';
  console.log(victimMoved && moved.length === 0
    ? 'PASS  overriding ' + victim + ' moved it and none of the other ' + peers.length + ' blocks'
    : 'FAIL  victim moved=' + victimMoved + ', collateral=' + moved.length + ' ' + moved.slice(0, 5));
  if (!victimMoved || moved.length) ok = false;

  // 3 - a brand change reaches everything that should follow, and nothing else
  const wasSecondary = built.palette['--v-brand-secondary'];
  const expect = built.blocks.filter((n) => norm(base[n]) === norm(wasSecondary));
  const brandEdit = rows.map((r) => r.attribute === '--v-brand-secondary'
    ? Object.assign({}, r, { value: '#00c853' }) : r);
  await p.setContent('<style>' + sheet(brandEdit) + '</style>');
  const after3 = await read(p, built.blocks);
  const followed = expect.filter((n) => norm(after3[n]) === '#00c853');
  const strays = built.blocks.filter((n) => norm(base[n]) !== norm(wasSecondary) && after3[n] !== base[n]);
  console.log(followed.length === expect.length && strays.length === 0
    ? 'PASS  one brand edit moved all ' + expect.length + ' blocks on ' + wasSecondary + ', and no others'
    : 'FAIL  followed ' + followed.length + '/' + expect.length + ', strays ' + strays.length);
  if (followed.length !== expect.length || strays.length) ok = false;

  // 4 - row order
  let drift = 0;
  for (let i = 1; i <= 10; i++) {
    let s = i * 7919 + 13;
    const r = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const sh = rows.slice();
    for (let k = sh.length - 1; k > 0; k--) { const j = Math.floor(r() * (k + 1)); [sh[k], sh[j]] = [sh[j], sh[k]]; }
    await p.setContent('<style>' + sheet(sh) + '</style>');
    const got = await read(p, names);
    drift += names.filter((n) => got[n] !== base[n]).length;
  }
  console.log(drift === 0 ? 'PASS  identical across 10 randomised row orders'
                          : 'FAIL  ' + drift + ' values changed with row order');
  if (drift) ok = false;

  await b.close();
  process.exit(ok ? 0 : 1);
})();

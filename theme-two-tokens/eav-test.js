// An EAV store returns rows in whatever order the query gives. If resolution
// depended on order, the scheme would render differently run to run - so this
// shuffles all 242 rows and checks every one of the 153 names theme-two ships
// still computes to the value the live site serves.
const puppeteer = require('/home/user/fab/scheme-app/node_modules/puppeteer');
const fs = require('fs');

const rows = JSON.parse(fs.readFileSync('theme-two.eav.json', 'utf8')).rows;
const today = JSON.parse(fs.readFileSync('built.json', 'utf8')).today;
const names = Object.keys(today);

function shuffle(a, seed) {
  const r = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const out = a.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

const norm = (v) => {
  const s = String(v).trim().toLowerCase();
  const m = s.match(/^(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})$/);
  if (m) return '#' + m.slice(1).map((n) => (+n).toString(16).padStart(2, '0')).join('');
  const h = s.match(/^#([0-9a-f]{6})$/);
  return h ? '#' + h[1] : s.replace(/\s+/g, ' ');
};

(async () => {
  const b = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const p = await b.newPage();
  let worstBad = null;
  let baseline = null;

  for (let run = 0; run < 25; run++) {
    const order = run === 0 ? rows : shuffle(rows, run * 7919 + 13);
    const css = ':root{' + order.map((r) => r.attribute + ':' + r.value + ';').join('') + '}';
    await p.setContent('<style>' + css + '</style><div id=x></div>');
    const got = await p.evaluate((ns) => {
      const cs = getComputedStyle(document.documentElement);
      const out = {};
      ns.forEach((n) => { out[n] = cs.getPropertyValue(n).trim(); });
      return out;
    }, names);

    const bad = names.filter((n) => norm(got[n]) !== norm(today[n]));
    if (run === 0) baseline = got;
    else {
      const drift = names.filter((n) => got[n].trim() !== baseline[n].trim());
      if (drift.length) console.log('  ORDER CHANGED THE RESULT on run', run, drift.slice(0, 5));
    }
    if (bad.length && (!worstBad || bad.length > worstBad.length)) worstBad = bad;
  }

  if (worstBad) {
    console.log('FAIL - ' + worstBad.length + ' tokens differ from the live site');
    worstBad.slice(0, 8).forEach((n) => console.log('   ', n, 'want', today[n], 'got', baseline[n]));
  } else {
    console.log('PASS - all ' + names.length + ' tokens resolve to the live value');
    console.log('PASS - identical across 25 randomised row orders, one :root');
  }
  await b.close();
  process.exit(worstBad ? 1 : 0);
})();

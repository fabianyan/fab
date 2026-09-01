# The rules, expressed over EAV rows rather than over files.
#
# In a six-file layout the load order enforces the layering. In an EAV store
# there are no files and no order - so every rule the structure depends on has
# to be checked when a row is saved, or the structure is only a convention and
# will not survive contact with a deadline.
#
# Port this to whatever the CMS saves with. It needs the rows and nothing else.
import json, re, math, sys

rows = json.load(open('theme-two.eav.json'))['rows']
by_name = {r['attribute']: r for r in rows}
fail, warn = [], []

LITERAL_OK = {'brand', 'palette', 'scale', 'exception'}
HEX = re.compile(r'#[0-9a-fA-F]{3,8}\b')
VAR = re.compile(r'^var\((--[A-Za-z0-9_-]+)\)$')

# 1 - a colour is written down once, and only in a row that is allowed to hold one
for r in rows:
    if HEX.search(r['value']) and r['layer'] not in LITERAL_OK:
        fail.append('%s is a %s row but contains a literal colour %s'
                    % (r['attribute'], r['layer'], r['value']))

# 2 - no two palette rows hold the same colour
seen = {}
for r in rows:
    if r['layer'] not in ('brand', 'palette'): continue
    m = HEX.fullmatch(r['value'].strip())
    if not m: continue
    key = r['value'].strip().lower()
    if key in seen:
        fail.append('%s duplicates the colour in %s (%s) - make one a role'
                    % (r['attribute'], seen[key], key))
    seen[key] = r['attribute']

# 3 - a role or alias row points at a name that exists
for r in rows:
    if r['layer'] not in ('role', 'alias'): continue
    m = VAR.match(r['value'].strip())
    if not m:
        if r['layer'] == 'role':
            fail.append('%s is a role but does not hold a var()' % r['attribute'])
        continue
    if m.group(1) not in by_name:
        fail.append('%s points at %s, which no row defines' % (r['attribute'], m.group(1)))

# 4 - an alias reaches a role, not the palette (the neutral ramp is a scale)
for r in rows:
    if r['layer'] != 'alias': continue
    m = VAR.match(r['value'].strip())
    if not m: continue
    t = by_name.get(m.group(1))
    if t and t['layer'] in ('brand', 'palette') and not re.match(r'--v-neutral-\d+$', m.group(1)):
        fail.append('%s reads %s directly - it should read a role'
                    % (r['attribute'], m.group(1)))

# 5 - no cycles
def chase(name, seen=None):
    seen = seen or []
    if name in seen: return seen + [name]
    r = by_name.get(name)
    if not r: return None
    m = VAR.match(r['value'].strip())
    return chase(m.group(1), seen + [name]) if m else None
for r in rows:
    c = chase(r['attribute'])
    if c: fail.append('cycle: ' + ' -> '.join(c))

# 6 - exception rows stay comma triples and still match a palette colour
palette_hex = {v.strip().lower() for v in
               (r['value'] for r in rows if r['layer'] in ('brand', 'palette'))}
for r in rows:
    if r['layer'] != 'exception': continue
    m = re.fullmatch(r'\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*', r['value'])
    if not m:
        fail.append('%s must stay a comma triple - it is used as rgba(var(), a)' % r['attribute'])
        continue
    h = '#%02x%02x%02x' % tuple(int(g) for g in m.groups())
    if h not in palette_hex:
        fail.append('%s (%s) has drifted from every palette colour' % (r['attribute'], h))

# 7 - no two palette colours a person cannot tell apart, unless a note says why
def lab(h):
    h = h.lstrip('#')
    r, g, b = (int(h[i:i+2], 16) for i in (0, 2, 4))
    f = lambda c: (c/255)/12.92 if c/255 <= .04045 else (((c/255)+.055)/1.055)**2.4
    r, g, b = f(r), f(g), f(b)
    X, Y, Z = (r*.4124+g*.3576+b*.1805)/.95047, r*.2126+g*.7152+b*.0722, (r*.0193+g*.1192+b*.9505)/1.08883
    k = lambda t: t**(1/3) if t > .008856 else 7.787*t+16/116
    fx, fy, fz = k(X), k(Y), k(Z)
    return (116*fy-16, 500*(fx-fy), 200*(fy-fz))
cols = [(r['attribute'], r['value'].strip().lower(), r.get('note', ''))
        for r in rows if r['layer'] in ('brand', 'palette') and HEX.fullmatch(r['value'].strip())]
for i in range(len(cols)):
    for j in range(i+1, len(cols)):
        (n1, v1, t1), (n2, v2, t2) = cols[i], cols[j]
        if v1 == v2: continue
        a, b = lab(v1), lab(v2)
        d = math.sqrt(sum((a[k]-b[k])**2 for k in range(3)))
        if d < 3.0 and 'deliberate' not in (t1 + t2):
            warn.append('%s %s and %s %s are dE %.2f apart - one colour, two names?'
                        % (n1, v1, n2, v2, d))

print('%d rows checked' % len(rows))
print('%d rule violations' % len(fail))
for f in fail[:20]: print('  FAIL', f)
print('%d warnings (need a note, not a fix)' % len(warn))
for w in warn[:6]: print('  WARN', w)
sys.exit(1 if fail else 0)

import re, json, math
from collections import defaultdict

SRC = '../onlyracing/new.css'
text = open(SRC).read()
decl = re.compile(r'(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);')
tokens = {}
order = []
for m in decl.finditer(text):
    name, val = m.group(1), m.group(2).strip()
    tokens[name] = val
    order.append(name)

def resolve(name, seen=None):
    seen = seen or set()
    if name in seen: return tokens.get(name, '')
    seen.add(name)
    v = tokens.get(name, '')
    m = re.fullmatch(r'var\((--[A-Za-z0-9_-]+)\)', v.strip())
    if m: return resolve(m.group(1), seen)
    return v

resolved = {n: resolve(n) for n in order}

# ---- colour helpers -------------------------------------------------
def to_rgb(v):
    v = v.strip()
    m = re.fullmatch(r'#([0-9a-fA-F]{6})', v)
    if m:
        h = m.group(1)
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    m = re.fullmatch(r'#([0-9a-fA-F]{3})', v)
    if m:
        h = m.group(1)
        return tuple(int(c*2, 16) for c in h)
    m = re.fullmatch(r'\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*', v)
    if m:
        return tuple(int(g) for g in m.groups())
    return None

def to_lab(rgb):
    def f(c):
        c = c/255
        return c/12.92 if c <= 0.04045 else ((c+0.055)/1.055) ** 2.4
    r, g, b = (f(c) for c in rgb)
    x = (r*0.4124+g*0.3576+b*0.1805)/0.95047
    y = (r*0.2126+g*0.7152+b*0.0722)
    z = (r*0.0193+g*0.1192+b*0.9505)/1.08883
    def h(t):
        return t ** (1/3) if t > 0.008856 else 7.787*t + 16/116
    fx, fy, fz = h(x), h(y), h(z)
    return (116*fy-16, 500*(fx-fy), 200*(fy-fz))

def de(a, b):
    la, lb = to_lab(a), to_lab(b)
    return math.sqrt(sum((la[i]-lb[i])**2 for i in range(3)))

colours = {n: to_rgb(v) for n, v in resolved.items() if to_rgb(v)}

# ---- 1. exact duplicates -------------------------------------------
by_rgb = defaultdict(list)
for n, rgb in colours.items():
    by_rgb[rgb].append(n)
exact = {k: v for k, v in by_rgb.items() if len(v) > 1}

# ---- 2. same value, non-colour --------------------------------------
by_val = defaultdict(list)
for n in order:
    if n in colours: continue
    if re.match(r'--v-type-.*-font-weight$', n): continue   # handled below
    by_val[resolved[n]].append(n)
dup_other = {k: v for k, v in by_val.items() if len(v) > 1}

# ---- 3. near-duplicate colours --------------------------------------
names = sorted(colours)
near = []
for i in range(len(names)):
    for j in range(i+1, len(names)):
        a, b = names[i], names[j]
        if colours[a] == colours[b]: continue
        d = de(colours[a], colours[b])
        if d < 3.0:
            near.append((round(d, 2), a, resolved[a], b, resolved[b]))
near.sort()

# ---- 4. type styles: identical (size, line-height, weight) ----------
styles = defaultdict(dict)
for n in order:
    m = re.fullmatch(r'--v-type-(.+)-(font-size|line-height|font-weight)', n)
    if m:
        styles[m.group(1)][m.group(2)] = resolved[n]
trip = defaultdict(list)
for style, parts in styles.items():
    if len(parts) == 3:
        trip[(parts['font-size'], parts['line-height'], parts['font-weight'])].append(style)
dup_styles = {k: v for k, v in trip.items() if len(v) > 1}

# ---- 5. how many names a brand must touch to change one colour ------
brand = {
  'primary':   ['#ffdf1b', '#ffe85c'],
  'secondary': ['#188664', '#2ab98c', '#2ed9a3'],
  'tertiary':  ['#ca22da', '#ef47ff', '#f47dff'],
  'subscribe': ['#f55800', '#d23e00', '#ffb186'],
}
reach = {}
for label, hexes in brand.items():
    hit = []
    for h in hexes:
        rgb = to_rgb(h)
        hit += by_rgb.get(rgb, [])
    reach[label] = sorted(set(hit))

out = {
  'total': len(order),
  'colours': len(colours),
  'distinct_colours': len(by_rgb),
  'exact': {('#%02x%02x%02x' % k): v for k, v in sorted(exact.items(), key=lambda kv: -len(kv[1]))},
  'dup_other': dup_other,
  'near': near,
  'dup_styles': {' / '.join(k): v for k, v in dup_styles.items()},
  'reach': reach,
  'literal_weights': sum(1 for n in order if re.search(r'font-weight$', n) and not resolved[n].startswith('var')),
  'weight_refs': sum(1 for n in order if re.search(r'font-weight$', n) and tokens[n].startswith('var')),
}
json.dump(out, open('analysis.json', 'w'), indent=1)

print('tokens', out['total'], '| colour tokens', out['colours'], '| distinct colours', out['distinct_colours'])
print()
print('EXACT DUPLICATE COLOURS (one colour, many names):')
for h, ns in out['exact'].items():
    print(' ', h, len(ns), 'names:', ', '.join(n.replace('--v-palette-', '') for n in ns))
print()
print('IDENTICAL NON-COLOUR VALUES:')
for v, ns in dup_other.items():
    print(' ', v, '->', ', '.join(ns))
print()
print('NEAR-DUPLICATE COLOURS (delta-E < 3, indistinguishable):')
for d, a, av, b, bv in near:
    print('  dE %.2f' % d, a.replace('--v-palette-',''), av, '~', b.replace('--v-palette-',''), bv)
print()
print('TYPE STYLES WITH IDENTICAL size/line-height/weight:')
for k, v in out['dup_styles'].items():
    print(' ', k, '->', ', '.join(v))
print()
print('NAMES A BRAND MUST EDIT TO MOVE ONE BRAND COLOUR:')
for k, v in reach.items():
    print(' ', k, len(v), 'names')

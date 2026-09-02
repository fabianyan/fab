import json, re, collections
b = json.load(open('full.built.json'))
rows = json.load(open('full.eav.json'))['rows']
val = {r['attribute']: r['value'] for r in rows}
REF = re.compile(r'^var\(\s*(--[A-Za-z0-9_-]+)\s*\)$')

# hop depth actually walked to answer "why is this colour"
def depth(n, d=0, seen=None):
    seen = seen or set()
    if n in seen or d > 12: return d
    seen.add(n)
    m = REF.match(val.get(n, ''))
    return depth(m.group(1), d + 1, seen) if m else d
worst = max(((depth(n), n) for n in b['blocks']), key=lambda t: t[0])
hops = collections.Counter(depth(n) for n in b['blocks'])
print('hops from a block to its literal:', dict(sorted(hops.items())), ' worst:', worst[1])

# roles nothing points at
used = {m.group(1) for v in val.values() for m in [REF.match(v)] if m}
deadroles = [r for r in b['roles'] if r not in used]
print('roles nothing references: %d' % len(deadroles))
for r in deadroles: print('   ', r)

# neutral ramp monotonic? a higher number should be darker
def lum(h):
    h = h.lstrip('#'); r, g, bl = (int(h[i:i+2], 16) for i in (0, 2, 4))
    f = lambda c: (c/255)/12.92 if c/255 <= .03928 else (((c/255)+.055)/1.055)**2.4
    return .2126*f(r) + .7152*f(g) + .0722*f(bl)
ramp = sorted(((int(re.search(r'(\d+)$', k).group(1)), k, v)
               for k, v in b['palette'].items() if re.match(r'--v-neutral-\d+$', k)))
bad = [(a, c) for (a, _, av), (c, _, cv) in zip(ramp, ramp[1:]) if lum(av) < lum(cv)]
print('\nneutral ramp, dark-increasing:', 'MONOTONIC' if not bad else '%d inversions' % len(bad))
for a, c in bad:
    av = dict((n, v) for n, _, v in [(x[0], x[1], x[2]) for x in ramp])[a]
    cv = dict((n, v) for n, _, v in [(x[0], x[1], x[2]) for x in ramp])[c]
    print('    neutral-%s %s is DARKER than neutral-%s %s' % (a, av, c, cv))

# active welded to hover
pal = b['palette']
for fam in ('primary', 'secondary', 'tertiary'):
    h, a = pal.get('--v-brand-%s-hover' % fam), pal.get('--v-brand-%s-active' % fam)
    if h and a and h == a:
        print('\n--v-brand-%s-active is the same colour as -hover (%s): the state is not distinguishable' % (fam, h))
    elif h and not a:
        print('\n--v-brand-%s has no active step at all - hover is doing both jobs' % fam)

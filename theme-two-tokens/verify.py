# Parses the four generated files back, resolves every chain, and compares
# against the value theme-two ships today. A refactor that changes a pixel is
# not a refactor.
import re, json, sys

tokens = {}
for f in ('1-palette.css', '2-roles.css', '3-type.css', '4-aliases.css', '5-exceptions.css'):
    for m in re.finditer(r'(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);', open(f).read()):
        tokens[m.group(1)] = m.group(2).strip()

def resolve(name, seen=None):
    seen = seen or set()
    if name in seen: return '<cycle>'
    seen.add(name)
    v = tokens.get(name)
    if v is None: return '<missing>'
    m = re.fullmatch(r'var\(\s*(--[A-Za-z0-9_-]+)\s*\)', v)
    return resolve(m.group(1), seen) if m else v

def same(a, b):
    def n(v):
        v = v.strip().lower()
        m = re.fullmatch(r'\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*', v)
        return '#%02x%02x%02x' % tuple(int(g) for g in m.groups()) if m else v
    return n(a) == n(b)

today = json.load(open('built.json'))['today']
bad = []
for name, want in today.items():
    got = resolve(name)
    if not same(got, want):
        bad.append((name, want, got))

print('%d/%d tokens resolve to exactly the value theme-two ships today'
      % (len(today) - len(bad), len(today)))
for n, w, g in bad:
    print('  MISMATCH', n, 'today', w, '->', g)

# No component name may reach a palette entry without passing through a role,
# except the ones listed as exceptions - that is the rule the structure exists
# to enforce, so it is checked rather than trusted.
palette = set(json.load(open('built.json'))['palette'])
roles = set(json.load(open('built.json'))['roles'])
direct = []
for name in today:
    v = tokens.get(name, '')
    m = re.fullmatch(r'var\(\s*(--[A-Za-z0-9_-]+)\s*\)', v)
    neutral = m and re.match(r'--v-neutral-\d+$', m.group(1))
    if m and m.group(1) in palette and name not in roles and not neutral:
        direct.append((name, m.group(1)))
print('%d component names reach the palette without a role (the neutral ramp is allowed)' % len(direct))
for n, t in direct[:12]:
    print('  DIRECT', n, '->', t)

# The exception tokens duplicate a palette colour by hand. Nothing keeps them
# in step, so drift is checked rather than hoped for.
drift = []
for name, v in tokens.items():
    if not name.endswith('-rgb'): continue
    m = re.fullmatch(r'\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*', v)
    if not m:
        drift.append((name, v, 'not a comma triple - rgba(var()) will break'))
        continue
    hexv = '#%02x%02x%02x' % tuple(int(g) for g in m.groups())
    if hexv not in set(json.load(open('built.json'))['palette'].values()):
        drift.append((name, v, hexv + ' is not a palette colour'))
print('%d of %d exception tokens still match a palette colour'
      % (sum(1 for n in tokens if n.endswith('-rgb')) - len(drift),
         sum(1 for n in tokens if n.endswith('-rgb'))))
for d in drift: print('  DRIFT', *d)
sys.exit(1 if bad or drift else 0)

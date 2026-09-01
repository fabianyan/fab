# Rebuild with the block layer where it belongs.
#
#   brand -> palette -> role -> block          alias hangs off role, not in the chain
#
# Two rules learned the hard way:
#  - every block keeps its own row, because that row IS the per-widget override
#  - no existing distinction is collapsed: a role per referenced palette name,
#    so two names that happen to share a colour today can still diverge later.
#    The dedupe happens at the palette layer only, where a colour is a colour.
import json, re, collections
from collections import OrderedDict

rows = json.load(open('../tokens.json'))['rows']
raw = OrderedDict((r['name'], r['raw'].strip()) for r in rows)
sect = {r['name']: r['section'] for r in rows}
blockof = {r['name']: r.get('block') for r in rows}

REF = re.compile(r'^var\(\s*(--[A-Za-z0-9_-]+)\s*\)$')

def resolve(n, seen=None):
    seen = seen or set()
    if n in seen: return raw.get(n, '')
    seen.add(n)
    m = REF.match(raw.get(n, ''))
    return resolve(m.group(1), seen) if m else raw.get(n, '')

R = {n: resolve(n) for n in raw}

PAL   = [n for n in raw if sect[n].startswith('1.')]
TYPE  = [n for n in raw if sect[n].startswith('2.')]
BLOCK = [n for n in raw if sect[n].startswith('3.')]

# ---- palette: one name per distinct colour ---------------------------
def norm(v):
    v = v.strip().lower()
    m = re.fullmatch(r'(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})', v)
    return '#%02x%02x%02x' % tuple(int(g) for g in m.groups()) if m else v
iscol = lambda v: bool(re.fullmatch(r'#[0-9a-fA-F]{3,8}|(\d{1,3}\s*,\s*){2}\d{1,3}', v.strip()))

BRAND_ROLE = re.compile(r'--v-palette-(brand|accent-subscribe|danger|star)')
groups = OrderedDict()
for n in PAL:
    if not iscol(R[n]): continue
    groups.setdefault(norm(R[n]), []).append(n)

def canon(hexv, names):
    for n in names:
        m = re.fullmatch(r'--v-palette-brand-(\w+?)-(default|hover|active)', n)
        if m: return '--v-brand-%s%s' % (m.group(1), '' if m.group(2) == 'default' else '-' + m.group(2))
    for n in names:
        m = re.fullmatch(r'--v-palette-accent-subscribe-(\w+)', n)
        if m: return '--v-brand-subscribe' + ('' if m.group(1) == 'default' else '-' + m.group(1))
    for n in names:
        if n == '--v-palette-danger-default': return '--v-brand-danger'
        if n == '--v-palette-star-filled':    return '--v-brand-star'
    for n in names:
        m = re.fullmatch(r'--v-palette-neutral-(\d+)', n)
        if m: return '--v-neutral-' + m.group(1)
    return '--v-' + min(names, key=len).replace('--v-palette-', '')

palette, canon_of = OrderedDict(), {}
for hexv, names in groups.items():
    c = canon(hexv, names)
    palette[c] = hexv
    for n in names: canon_of[n] = c

BRAND = [k for k in palette if k.startswith('--v-brand-')]

# ---- roles: one per palette name the theme actually references -------
# Nothing is merged here. Two palette names that share a colour get two roles
# pointing at the same palette entry, so either can be moved on its own later.
referenced = collections.Counter()
for n in BLOCK + PAL + TYPE:
    m = REF.match(raw[n])
    if m and m.group(1) in canon_of: referenced[m.group(1)] += 1

def rolename(pal_name):
    s = pal_name.replace('--v-palette-', '')
    s = re.sub(r'^brand-(\w+?)-default$', r'action-\1', s)
    s = re.sub(r'^brand-(\w+?)-(hover|active)$', r'action-\1-\2', s)
    s = re.sub(r'^accent-', '', s)
    s = re.sub(r'^neutral-(\d+)$', r'neutral-\1', s)
    return '--v-role-' + s

roles, role_of = OrderedDict(), {}
for pal_name in referenced:
    rn = rolename(pal_name)
    roles[rn] = 'var(%s)' % canon_of[pal_name]
    role_of[pal_name] = rn

dead = [n for n in PAL if iscol(R[n]) and n not in referenced]

# ---- blocks: keep every row, repoint at the role ---------------------
blocks = OrderedDict()
for n in BLOCK:
    m = REF.match(raw[n])
    blocks[n] = 'var(%s)' % role_of[m.group(1)] if (m and m.group(1) in role_of) else raw[n]

# ---- typography ------------------------------------------------------
typ = OrderedDict((n, 'var(%s)' % role_of[REF.match(raw[n]).group(1)]
                  if (REF.match(raw[n]) and REF.match(raw[n]).group(1) in role_of) else raw[n])
                 for n in TYPE)

# ---- alias: the old palette names, off to the side -------------------
alias = OrderedDict((n, 'var(%s)' % role_of[n]) for n in PAL if n in role_of)
for n in PAL:
    if n not in alias: alias[n] = raw[n]

LAYERS = [('brand', OrderedDict((k, palette[k]) for k in BRAND)),
          ('palette', OrderedDict((k, v) for k, v in palette.items() if k not in BRAND)),
          ('role', roles), ('type', typ), ('block', blocks), ('alias', alias)]

eav = []
for layer, d in LAYERS:
    for k, v in d.items():
        eav.append(OrderedDict(attribute=k, value=v, layer=layer,
                               editable=(layer in ('brand', 'block')),
                               block=blockof.get(k) or ''))
json.dump({'entity': 'theme-two', 'rows': eav}, open('full.eav.json', 'w'), indent=1)

out = ['/* theme-two - %d EAV rows, one :root. Block layer intact. */' % len(eav),
       '/* brand -> palette -> role -> block.  alias hangs off role, not in the chain. */',
       ':root {']
for layer, d in LAYERS:
    out.append('  /* %s (%d) */' % (layer.upper(), len(d)))
    out += ['  %s: %s;' % (k, v) for k, v in d.items()]
    out.append('')
out.append('}')
open('theme-two-full.css', 'w').write('\n'.join(out) + '\n')

json.dump({'today': R, 'palette': palette, 'roles': roles, 'blocks': list(blocks),
           'dead': dead, 'brand': BRAND}, open('full.built.json', 'w'), indent=1)
print('rows %d | brand %d | palette %d | roles %d | type %d | blocks %d | alias %d'
      % (len(eav), len(BRAND), len(palette) - len(BRAND), len(roles), len(typ), len(blocks), len(alias)))
print('editable rows (brand + every block): %d' % sum(1 for r in eav if r['editable']))
print('palette names nothing references: %d %s' % (len(dead), [d.replace('--v-palette-','') for d in dead]))

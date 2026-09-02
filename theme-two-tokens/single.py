# One :root, one row per token - the shape an EAV store can actually emit.
# Layer is metadata about a row, not a position in a file, because a query
# returns rows in whatever order it likes.
import json, re
from collections import OrderedDict

b = json.load(open('built.json'))
palette, roles, sizes, leads, alias, today = (
    b['palette'], b['roles'], b['sizes'], b['leads'], b['alias'], b['today'])
exceptions = OrderedDict()
for m in re.finditer(r'(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);', open('5-exceptions.css').read()):
    exceptions[m.group(1)] = m.group(2).strip()

BRAND = [k for k in palette if k.startswith('--v-brand-')] + \
        ['--v-type-family-base', '--v-type-family-titles']

rows = []
def add(name, value, layer, editable, note=''):
    rows.append(OrderedDict(attribute=name, value=value, layer=layer,
                            editable=editable, note=note))

for k, v in palette.items():
    if k in BRAND:
        add(k, v, 'brand', True, 'the brand chooses this')
    else:
        add(k, v, 'palette', False, 'one name per colour; edit via the brand rows')
for k in ('--v-type-family-base', '--v-type-family-titles'):
    add(k, today[k], 'brand', True, 'the brand chooses this')
for k, v in roles.items():
    add(k, v, 'role', False, 'what a colour means; repoint to re-skin')
for k, v in list(sizes.items()) + list(leads.items()):
    add(k, v, 'scale', False, 'shared type scale')
for k, v in alias.items():
    if k in ('--v-type-family-base', '--v-type-family-titles'):
        continue
    add(k, v, 'alias', False, 'name theme-two ships today; delete when unread')
for k, v in exceptions.items():
    add(k, v, 'exception', False, 'rgba(var()) consumer - must stay a triple')

seen = set()
for r in rows:
    assert r['attribute'] not in seen, 'duplicate row: ' + r['attribute']
    seen.add(r['attribute'])

json.dump({'entity': 'theme-two', 'rows': rows}, open('theme-two.eav.json', 'w'), indent=1)

with open('theme-two.eav.csv', 'w') as f:
    f.write('entity,attribute,value,layer,editable\n')
    for r in rows:
        v = r['value'].replace('"', '""')
        f.write('theme-two,%s,"%s",%s,%s\n' % (r['attribute'], v, r['layer'], str(r['editable']).lower()))

# The stylesheet a CMS would render from those rows: one :root, one pass.
LAYERS = [('brand', 'BRAND - the only rows a brand edits'),
          ('palette', 'PALETTE - one name per colour'),
          ('role', 'ROLES - what a colour means'),
          ('scale', 'TYPE SCALE'),
          ('alias', 'ALIASES - the names theme-two ships today'),
          ('exception', 'EXCEPTIONS - rgba(var()) consumers')]
out = ['/* theme-two - generated from %d EAV rows.' % len(rows),
       '',
       '   One :root, exactly as today. The grouping below is comment text for',
       '   humans: custom properties resolve at computed-value time, so a var()',
       '   pointing at a name declared further down resolves the same as one',
       '   pointing up. Row order out of the database does not matter. */',
       ':root {']
for layer, title in LAYERS:
    out.append('  /* %s */' % title)
    for r in rows:
        if r['layer'] == layer:
            out.append('  %s: %s;' % (r['attribute'], r['value']))
    out.append('')
out.append('}')
open('theme-two.css', 'w').write('\n'.join(out) + '\n')

from collections import Counter
c = Counter(r['layer'] for r in rows)
print('%d rows: ' % len(rows) + ', '.join('%s %d' % (k, c[k]) for k, _ in LAYERS))
print('editable by a brand: %d' % sum(1 for r in rows if r['editable']))

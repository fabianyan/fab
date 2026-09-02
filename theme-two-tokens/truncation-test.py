# Does my parser lose anything at a space? Feed it the real values from the
# 647-token capture that contain spaces - the class the critique says is suspect.
import re, json
decl = re.compile(r'(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);')
VAR_STRICT = re.compile(r'^var\((--[A-Za-z0-9_-]+)\)$')          # what I shipped
VAR_LOOSE  = re.compile(r'^var\(\s*(--[A-Za-z0-9_-]+)\s*[,)]')   # what it should be

rows = json.load(open('../tokens.json'))['rows']
spacey = [r for r in rows if ' ' in r['raw'].strip()]
css = ':root{\n' + '\n'.join('  %s: %s;' % (r['name'], r['raw']) for r in spacey) + '\n}'
parsed = {m.group(1): m.group(2).strip() for m in decl.finditer(css)}

lost = [(r['name'], r['raw'], parsed.get(r['name'])) for r in spacey
        if parsed.get(r['name']) != r['raw'].strip()]
print('%d space-containing values round-tripped, %d lost characters' % (len(spacey), len(lost)))
for n, want, got in lost: print('  LOST', n, '\n    want', want, '\n    got ', got)

print()
print('var() reference detection on the same values:')
for r in spacey:
    v = r['raw'].strip()
    if not v.startswith('var('): continue
    s, l = VAR_STRICT.match(v), VAR_LOOSE.match(v)
    print('  %-72s strict=%s loose=%s' % (v[:70], 'HIT' if s else 'MISS', l.group(1) if l else 'MISS'))

# Break the rows on purpose, one rule at a time, and confirm the validator
# catches it. A check that has never failed is not a check.
import json, subprocess, shutil, copy

base = json.load(open('theme-two.eav.json'))
shutil.copy('theme-two.eav.json', '.eav.bak')

CASES = [
 ('a hex smuggled into a role row',
  lambda r: [dict(x, value='#ff0000') if x['attribute'] == '--v-role-action-primary' else x for x in r]),
 ('the same colour given a second palette name',
  lambda r: r + [dict(attribute='--v-palette-sneaky', value='#ffdf1b', layer='palette', editable=False, note='')]),
 ('a role pointing at a name nothing defines',
  lambda r: [dict(x, value='var(--v-brand-nonexistent)') if x['attribute'] == '--v-role-selected' else x for x in r]),
 ('a component reading the palette instead of a role',
  lambda r: [dict(x, value='var(--v-brand-tertiary)') if x['attribute'] == '--v-palette-accent-highlight' else x for x in r]),
 ('an rgb exception turned into a hex',
  lambda r: [dict(x, value='#000000') if x['attribute'] == '--v-palette-nav-list-rgb' else x for x in r]),
 ('an rgb exception drifting off its palette colour',
  lambda r: [dict(x, value='9, 9, 9') if x['attribute'] == '--v-palette-nav-list-rgb' else x for x in r]),
 ('a cycle between two roles',
  lambda r: [dict(x, value='var(--v-role-selected)') if x['attribute'] == '--v-role-highlight'
             else (dict(x, value='var(--v-role-highlight)') if x['attribute'] == '--v-role-selected' else x) for x in r]),
]

ok = 0
for name, mutate in CASES:
    rows = mutate(copy.deepcopy(base['rows']))
    json.dump({'entity': 'theme-two', 'rows': rows}, open('theme-two.eav.json', 'w'), indent=1)
    p = subprocess.run(['python3', 'eav-rules.py'], capture_output=True, text=True)
    caught = p.returncode != 0
    print(('CAUGHT  ' if caught else 'MISSED  ') + name)
    if caught:
        ok += 1
        line = [l for l in p.stdout.splitlines() if l.strip().startswith('FAIL')]
        if line: print('        ' + line[0].strip()[5:].strip())

shutil.move('.eav.bak', 'theme-two.eav.json')
print()
print('%d of %d violations caught' % (ok, len(CASES)))

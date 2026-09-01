import re, json, math
from collections import defaultdict, OrderedDict

text = open('../onlyracing/new.css').read()
decl = re.compile(r'(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);')
tokens = OrderedDict()
for m in decl.finditer(text):
    tokens[m.group(1)] = m.group(2).strip()

def resolve(name, seen=None):
    seen = seen or set()
    if name in seen: return tokens.get(name, '')
    seen.add(name)
    v = tokens.get(name, '')
    m = re.fullmatch(r'var\(\s*(--[A-Za-z0-9_-]+)\s*\)', v.strip())
    return resolve(m.group(1), seen) if m else v

R = {n: resolve(n) for n in tokens}

# ---------------------------------------------------------------- palette
# One canonical name per distinct colour. Brand names win, then the neutral
# ramp, then whatever accent name is left - so the name that survives is the
# one a designer would look for.
def norm(v):
    v = v.strip()
    m = re.fullmatch(r'\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*', v)
    if m: return '#%02x%02x%02x' % tuple(int(g) for g in m.groups())
    return v.lower()

colour_names = [n for n in tokens if n.startswith('--v-palette-') and
                re.match(r'^(#|[\s\d,]+$)', R[n].strip())]
by_colour = OrderedDict()
for n in colour_names:
    by_colour.setdefault(norm(R[n]), []).append(n)

BRAND = {
 '#ffdf1b': '--v-brand-primary',        '#ffe85c': '--v-brand-primary-hover',
 '#188664': '--v-brand-secondary',      '#2ab98c': '--v-brand-secondary-hover',
 '#2ed9a3': '--v-brand-secondary-active',
 '#ca22da': '--v-brand-tertiary',       '#ef47ff': '--v-brand-tertiary-hover',
 '#f47dff': '--v-brand-tertiary-active',
 '#f55800': '--v-brand-subscribe',      '#d23e00': '--v-brand-subscribe-hover',
 '#ffb186': '--v-brand-subscribe-disabled',
 '#bb0728': '--v-brand-danger',         '#ffc42b': '--v-brand-star',
}
def canonical(hexv, names):
    if hexv in BRAND: return BRAND[hexv]
    for n in names:
        m = re.fullmatch(r'--v-palette-neutral-(\d+)', n)
        if m: return '--v-neutral-' + m.group(1)
    return '--v-' + min((n for n in names), key=len).replace('--v-palette-', '')

palette = OrderedDict()
canon_of = {}
for hexv, names in by_colour.items():
    c = canonical(hexv, names)
    palette[c] = hexv
    for n in names: canon_of[n] = c

# ---------------------------------------------------------------- roles
# What a colour MEANS. Components read these, never the palette, so a brand
# swap is a palette edit and nothing else moves.
ROLES = [
 ('action-primary',            '--v-brand-primary'),
 ('action-primary-hover',      '--v-brand-primary-hover'),
 ('action-primary-active',     '--v-brand-primary-hover'),
 ('on-action-primary',         '--v-neutral-900'),
 ('action-secondary',          '--v-brand-secondary'),
 ('action-secondary-hover',    '--v-brand-secondary-hover'),
 ('action-secondary-active',   '--v-brand-secondary-active'),
 ('action-tertiary',           '--v-brand-tertiary'),
 ('action-tertiary-hover',     '--v-brand-tertiary-hover'),
 ('action-tertiary-active',    '--v-brand-tertiary-active'),
 ('action-subscribe',          '--v-brand-subscribe'),
 ('action-subscribe-hover',    '--v-brand-subscribe-hover'),
 ('action-subscribe-disabled', '--v-brand-subscribe-disabled'),
 ('selected',                  '--v-brand-secondary'),
 ('selected-muted',            '--v-brand-tertiary'),
 ('highlight',                 '--v-brand-tertiary'),
 ('link-visited',              '--v-brand-secondary-hover'),
 ('danger',                    '--v-brand-danger'),
 ('disabled',                  '--v-neutral-600'),
 ('surface-header',            '--v-neutral-975'),
 ('surface-footer',            '--v-accent-footer'),
 ('surface-search',            '--v-accent-search'),
 ('surface-hover-dark',        '--v-accent-hover-dark'),
 ('surface-hover-icon',        '--v-accent-hover-icon'),
 ('surface-hover-primary',     '--v-accent-hover-primary'),
 ('surface-inverse',           '--v-neutral-900'),
 ('border-strong',             '--v-accent-border-strong'),
 ('text-inverse',              '--v-neutral-000'),
 ('star-empty',                '--v-star-empty'),
 ('star-filled',              '--v-brand-star'),
]
roles = OrderedDict(('--v-role-' + k, 'var(%s)' % v) for k, v in ROLES)
role_target = {}
for k, v in ROLES:
    role_target.setdefault(v, '--v-role-' + k)

# ---------------------------------------------------------------- type
sizes, leads = OrderedDict(), OrderedDict()
SIZE_NAME = {'10px':'2xs','12px':'xs','14px':'s','16px':'m','17px':'m-plus','18px':'l',
             '20px':'xl','22px':'2xl','24px':'3xl','30px':'4xl','40px':'5xl','45px':'6xl'}
LEAD_NAME = {'normal':'normal','120%':'120','125%':'125','130%':'130','133%':'133',
             '135%':'135','136%':'136','137%':'137','138.5%':'138','140%':'140',
             '147%':'147','150%':'150','176%':'176'}
for n, v in R.items():
    if n.endswith('-font-size'): sizes['--v-type-size-' + SIZE_NAME[v]] = v
    if n.endswith('-line-height'): leads['--v-type-leading-' + LEAD_NAME[v]] = v
sizes = OrderedDict(sorted(sizes.items(), key=lambda kv: float(kv[1][:-2])))
leads = OrderedDict(sorted(leads.items(), key=lambda kv: (kv[1] == 'normal', float(kv[1][:-1]) if kv[1] != 'normal' else 0)))
size_of = {v: k for k, v in sizes.items()}
lead_of = {v: k for k, v in leads.items()}

# ---------------------------------------------------------------- aliases
alias = OrderedDict()
for n, raw in tokens.items():
    if n.endswith('-rgb'):
        alias[n] = None          # kept as a literal triple in 5-exceptions.css
    elif n in canon_of:
        target = canon_of[n]
        alias[n] = 'var(%s)' % (role_target.get(target) or target)
    elif n.endswith('-font-size'):   alias[n] = 'var(%s)' % size_of[R[n]]
    elif n.endswith('-line-height'): alias[n] = 'var(%s)' % lead_of[R[n]]
    elif n.endswith('-font-weight') or n.startswith('--v-type-weight'):
        alias[n] = raw if raw.startswith('var') else raw
    else:
        alias[n] = raw

def block(title, pairs, note=''):
    out = ['/* %s */' % title]
    if note: out.append('/* %s */' % note)
    out.append(':root {')
    for k, v in pairs.items(): out.append('  %s: %s;' % (k, v))
    out.append('}')
    return '\n'.join(out) + '\n'

open('1-palette.css','w').write(block(
  '1 - PALETTE: every colour in theme-two, each named exactly once.',
  palette,
  'A colour appears here or nowhere. 34 entries for what were 50 names.'))
open('2-roles.css','w').write(block(
  '2 - ROLES: what a colour means. Components read these, never the palette.',
  roles,
  'Repointing a role re-skins everything that uses it, in one edit.'))
open('3-type.css','w').write(block(
  '3 - TYPE SCALE: the sizes and line heights the styles are built from.',
  OrderedDict(list(sizes.items()) + list(leads.items())),
  '12 sizes and 13 line heights across 26 styles - see MERGE-CANDIDATES.md.'))
exceptions = OrderedDict((n, tokens[n]) for n in tokens if n.endswith('-rgb'))
for n in exceptions: alias.pop(n, None)
open('5-exceptions.css','w').write(block(
  '5 - EXCEPTIONS: the tokens no role can own, and why.',
  exceptions,
  'Consumed as rgba(var(--x), a), so they must stay comma triples - a hex here '
  'is invalid CSS. Each one duplicates a palette colour and cannot be kept in '
  'step automatically: verify.py fails if they drift. Migrate the consumers to '
  'color-mix(in srgb, var(--role) N%, transparent) and delete this file.'))
open('4-aliases.css','w').write(block(
  '4 - ALIASES: every name theme-two ships today, repointed. Nothing breaks.',
  alias,
  'Delete a line here only once no stylesheet reads that name.'))

json.dump({'palette': palette, 'roles': roles, 'sizes': sizes, 'leads': leads,
           'alias': alias, 'today': R}, open('built.json','w'), indent=1)
print('palette %d | roles %d | sizes %d | leadings %d | aliases %d' %
      (len(palette), len(roles), len(sizes), len(leads), len(alias)))

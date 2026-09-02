import json, re, math
from collections import OrderedDict
b = json.load(open('built.json'))
pal, R = b['palette'], b['today']

BRAND_KEYS = [k for k in pal if k.startswith('--v-brand-')]
FAMILIES = ['primary','secondary','tertiary','subscribe']

lines = ["/* 0 - BRAND: the whole creative surface. Nothing else is per-brand. */",
         "/* Load FIRST, before 1-palette.css. 15 values decide the skin. */",
         ":root {"]
for k in BRAND_KEYS: lines.append('  %s: %s;' % (k, pal[k]))
lines.append('  --v-type-family-base: %s;' % R['--v-type-family-base'])
lines.append('  --v-type-family-titles: %s;' % R['--v-type-family-titles'])
lines.append('}')
open('0-brand-theme-two.css','w').write('\n'.join(lines) + '\n')

tpl = ["/* 0 - BRAND template for a NEW brand.",
       "",
       "   Fill in the four default colours. Hover and active are derived, so a",
       "   brand can ship with four decisions instead of thirteen. Any derived",
       "   step can be overridden by writing it out - the derivation is a",
       "   starting point, not a rule. theme-two overrides all of them, because",
       "   its steps were chosen by eye. */",
       ":root {"]
for f in FAMILIES:
    tpl.append('  --v-brand-%s: #000000;            /* CHOOSE */' % f)
    tpl.append('  --v-brand-%s-hover: color-mix(in srgb, var(--v-brand-%s) 82%%, white);' % (f, f))
    tpl.append('  --v-brand-%s-active: color-mix(in srgb, var(--v-brand-%s) 70%%, white);' % (f, f))
tpl += ['  --v-brand-danger: #bb0728;         /* shared unless the brand says otherwise */',
        '  --v-brand-star: #ffc42b;',
        '  --v-type-family-base: "Lato", sans-serif;   /* CHOOSE */',
        '  --v-type-family-titles: "Lato", sans-serif; /* CHOOSE */',
        '}']
open('0-brand-NEW.css','w').write('\n'.join(tpl) + '\n')

# ---- contrast gate --------------------------------------------------
def rgb(h):
    h = h.lstrip('#'); return tuple(int(h[i:i+2],16) for i in (0,2,4))
def lum(c):
    def f(v):
        v/=255; return v/12.92 if v<=0.03928 else ((v+0.055)/1.055)**2.4
    r,g,bb = (f(x) for x in c); return 0.2126*r+0.7152*g+0.0722*bb
def ratio(a,b):
    la,lb = lum(rgb(a)), lum(rgb(b))
    hi,lo = max(la,lb), min(la,lb); return (hi+0.05)/(lo+0.05)

PAIRS = [
 ('button label on primary',   '--v-neutral-900', '--v-brand-primary'),
 ('button label on secondary', '--v-neutral-000', '--v-brand-secondary'),
 ('button label on tertiary',  '--v-neutral-000', '--v-brand-tertiary'),
 ('button label on subscribe', '--v-neutral-000', '--v-brand-subscribe'),
 ('label on danger',           '--v-neutral-000', '--v-brand-danger'),
 ('text on header',            '--v-neutral-000', '--v-neutral-975'),
 ('text on footer',            '--v-neutral-000', '--v-accent-footer'),
 ('text on search',            '--v-neutral-000', '--v-accent-search'),
 ('disabled label on page',    '--v-neutral-600', '--v-neutral-000'),
 ('body text on page',         '--v-neutral-900', '--v-neutral-000'),
]
rows = []
for label, fg, bg in PAIRS:
    r = ratio(pal[fg], pal[bg])
    rows.append((label, pal[fg], pal[bg], round(r,2), 'PASS' if r>=4.5 else ('LARGE-ONLY' if r>=3 else 'FAIL')))
json.dump(rows, open('contrast.json','w'), indent=1)
print('%-28s %-8s %-8s %6s  %s' % ('pair','text','behind','ratio','AA'))
for r in rows: print('%-28s %-8s %-8s %6s  %s' % r)
print()
print('%d of %d pass AA for body text (4.5:1)' % (sum(1 for r in rows if r[4]=='PASS'), len(rows)))

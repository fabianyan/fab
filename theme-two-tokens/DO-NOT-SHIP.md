# Do not ship this yet — it is missing the block layer

## What is wrong

This was generated from a 153-token scheme file. The real theme has **662**
tokens on the live page. The missing ~500 are the **block layer** —
`--v-fg-*`, `--v-surface-*`, `--v-border-*`, `--v-icon-*`, `--v-shadow-*`,
`--v-filter-*` — which is not in that file. It lives elsewhere.

Measured against the 647-token capture in `../scratchpad/tokens.json`:

| | count |
|---|---:|
| block-layer tokens | **503** |
| distinct blocks | **123** |
| of those, pointing at a `var()` | 471 |
| of those, holding a literal value | 32 |

Applying `theme-two.css` as the scheme would leave every one of those 503
names undefined. A custom property that is not defined does not fall back to
its previous value — the declaration using it is invalid at computed-value
time, and the property becomes inherited-or-initial. Roughly 123 components
lose their colours at once.

## Why the block layer exists

It is the per-widget override. `--v-fg-sticky-cta-*` can move without
`--v-fg-static-cta-*` moving, even though both currently resolve through
`--v-palette-brand-secondary-default` (39 blocks point at that one token).
Collapsing the block layer into shared roles removes exactly the capability
the EAV CMS is for.

The role layer in `2-roles.css` is still right, but it belongs **between**
the palette and the blocks, not instead of the blocks:

```
brand -> palette -> role -> block -> (alias, during migration only)
```

A block keeps its own row, so it can still be overridden per brand; its
default just points at a role instead of repeating a hex.

## Also wrong, found while checking

`var( --x )` written with spaces inside the parentheses was matched by none of
the strict regexes here, so such a value was treated as a literal: the
reference chain stopped and the "no direct palette read" rule passed silently.
Two of the 503 block tokens are written that way. **Fixed** in `verify.py`,
`eav-rules.py` and `build.py`.

Not a bug: values are not truncated at whitespace. `truncation-test.py` feeds
all nine space-containing values from the real capture through the parser —
nine round-trip, zero characters lost. `--v-palette-filter-nav-icon-default:
brightness(0)` is what the source file says, not something this pipeline
destroyed. It is still suspicious, because the token it appears to replace,
`--v-filter-bottom-tab-navigation`, is an eight-function chain
(`brightness(0) saturate(100%) invert(100%) …`) — but that truncation, if it
is one, happened upstream of here.

## Before this can ship

1. Rebuild from the **live capture**, not from a pasted file. The Scheme
   Editor reads all 662 tokens off the page; that is the source of truth, and
   using a fragment instead is what caused this.
2. Decide where blocks live — in the table (~740 rows, generated in full) or
   as static CSS concatenated after the generated block. Not neither.
3. Then the outstanding items: the inverted neutrals, the dead roles, and
   `active` welded to `hover`.
4. Put a delete date on the alias layer. It exists only to keep old names
   working during migration; without a date it is permanent, and it is the
   fifth hop a designer has to walk to answer "why is this button green".

# The rebuild, with the block layer where it belongs

Built from the **647-token capture** (`../../scratchpad/tokens.json`) — a
complete theme, all three sections. Not from the 153-token fragment that
produced the version in the parent directory.

```
brand -> palette -> role -> block          alias hangs off role, not in the chain
```

716 rows: 8 brand, 21 palette, 40 role, 101 type, **503 block**, 43 alias.

## What the tests establish

```
PASS  all 647 tokens resolve to today's value
PASS  overriding --v-fg-button moved it and none of the other 502 blocks
PASS  one brand edit moved all 53 blocks on #5f57fd, and no others
PASS  identical across 10 randomised row orders
```

The middle two are the point. The second is the per-widget override — the
capability the EAV CMS exists to sell — still working. The third is the thing
that was broken and is now fixed: one edit reaching everything it should, and
nothing it shouldn't. Both measured in Chrome against the real 647.

## Two rules, learned from getting it wrong

**Every block keeps its own row.** That row *is* the override. A block's
default points at a role instead of repeating a hex, which is the whole gain;
the row staying put is what preserves the feature.

**No existing distinction is collapsed.** There is a role per referenced
palette name, so two names that happen to share a colour today can still
diverge tomorrow. Deduplication happens at the palette layer only, where a
colour is just a colour. The previous build merged
`--v-palette-brand-primary-active` into `-hover` because they are both
`#ffe85c` — which quietly removed the ability to ever give `active` its own
colour. Same failure as dropping the block layer, smaller blast radius.

## Hop count

Measured, not estimated: 471 blocks are **2 hops** from a literal
(block → role → palette), 32 hold a literal directly. Brand adds one more for
the 8 brand entries. The alias layer is a dead-end branch off the roles, not a
link in the chain — deleting it changes nothing a block reads.

`audit.py` reports hop distribution, roles nothing references (**0** here; the
previous build had 6), and whether the neutral ramp is monotonic.

## Still to do

This is built from the **old** palette (`#ff6b00` primary). The live site now
serves a newer one. Re-run `build_full.py` against a fresh full capture of all
662 live tokens before shipping — a capture, not a pasted file.

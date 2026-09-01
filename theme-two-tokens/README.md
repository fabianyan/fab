# theme-two tokens, restructured

An audit of the 153 tokens `dev-onlyracing.clickto.bet` serves today, and a
restructure of them. Same site, same pixels, different shape.

| | today | here |
|---|---:|---:|
| colour names | 50 | **34** — one name per colour |
| names to change to move one brand colour | up to **7** | **1** |
| files a brand edits | the whole scheme | **1**, holding 15 values |

**153/153 tokens resolve to exactly the value theme-two ships today.**
`verify.py` parses the generated files back, resolves every chain and compares.
This migration cannot change a pixel — that is why it can ship before anything
is agreed about the look.

## Load order

```
0-brand-theme-two.css   15 values - the only per-brand file
1-palette.css           34 colours, each named once
2-roles.css             30 roles: what a colour means
3-type.css              12 sizes + 13 line heights
4-aliases.css           150 names theme-two ships today, repointed
5-exceptions.css        3 rgb triples - delete once consumers use color-mix()
```

Every stylesheet keeps reading the names it reads today. Nothing needs
migrating for this to go in.

## Reading the rest

- `STANDARDS.md` — the four rules, each enforced by a script rather than by
  memory, plus the contrast gate.
- `MERGE-CANDIDATES.md` — the changes that *do* move pixels: 31 colour pairs
  under ΔE 3, the line-height clusters, the two styles that are already
  identical. Design sign-off, not a rename.
- `0-brand-NEW.css` — what a new brand fills in. Four colours and two families;
  hover and active derive with `color-mix()` and any step can be overridden.

## Rerunning it

```
python3 analyse.py     # the audit: duplicates, near-duplicates, reach
python3 build.py       # regenerate 1- .. 5- from the source scheme
python3 brand.py       # brand file, new-brand template, contrast gate
python3 verify.py      # fails if any token drifts from today's value
```

`analyse.py` and `build.py` read `../onlyracing/new.css` — point them at
whichever scheme file is current.

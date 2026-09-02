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

## It stays one `:root`

`theme-two.css` is the whole scheme in a single `:root` block, exactly the
shape the CMS emits today. No files, no load order, no build step.

It is generated from `theme-two.eav.json` / `.csv` - 242 rows of
`entity, attribute, value, layer, editable`. The layering that makes a brand
change one edit is carried by the `layer` column, not by a file. A designer is
shown the 15 rows marked `editable`; the rest are seeded once.

**Row order is irrelevant**, which is the property EAV needs: custom properties
resolve at computed-value time, so a `var()` pointing at a name declared
further down resolves like one pointing up. `eav-test.js` shuffles all 242 rows
25 ways in Chrome and confirms all 153 names still land on the live value.

The numbered files are the same content split by layer, for reading and for
diffing. Ship either; they generate from the same rows.

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
python3 analyse.py          # the audit: duplicates, near-duplicates, reach
python3 build.py            # regenerate 1- .. 5- from the source scheme
python3 brand.py            # brand file, new-brand template, contrast gate
python3 single.py           # theme-two.css (one :root) + the EAV rows
python3 verify.py           # fails if any token drifts from today's value
python3 eav-rules.py        # the save-time validator, over rows alone
python3 eav-rules-test.py   # breaks the rows on purpose: 7/7 caught
node eav-test.js            # Chrome, 25 shuffled row orders
```

`eav-rules.py` is the one to port into the CMS. With no files there is no load
order to enforce the layering, so it has to be checked when a row is saved.

`analyse.py` and `build.py` read `../onlyracing/new.css` — point them at
whichever scheme file is current.

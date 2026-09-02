# How to produce the shippable theme

Six steps. Steps 1–3 are yours; 4–6 are one command each.

## 1. Capture the live site

Open the Scheme Editor, paste `https://dev-onlyracing.clickto.bet/` with the
Basic Auth fields filled, and load it.

**Check the status line says `662 variables loaded`.** If it says 153, or any
number near it, the capture did not get the block layer and everything after
this is wrong. That is the check that was missed last time.

## 2. Reset

Click **Reset all** before exporting. Any edit still in the panel is exported
as if it were the site's own value, and the export is meant to be a record of
what the site actually serves.

## 3. Export

**Export CSS… → "All CSS" → Download.**

"All CSS" keeps `var()` references instead of freezing each token to a literal,
which is what makes the layering recoverable. The other mode exports only what
changed and is not what this needs.

You get `dev-onlyracing.clickto.bet-scheme.css`. Confirm it has ~662 lines and
that `grep -c -- "--v-fg-" ` on it returns a few hundred, not zero.

## 4. Build

```
python3 build_full.py dev-onlyracing.clickto.bet-scheme.css
```

Prints the token counts it found by section, then the row counts it produced.
Writes `theme-two-full.css` (one `:root`) and `full.eav.json` (the rows).

Expect palette + typography + blocks to sum to your 662, and blocks to be in
the hundreds. **If blocks is 0, stop** — the export was the wrong mode.

## 5. Test

```
node full-test.js
```

All four must pass:

```
PASS  all NNN tokens resolve to today's value
PASS  overriding --v-fg-button moved it and none of the other NNN blocks
PASS  one brand edit moved all NN blocks on #xxxxxx, and no others
PASS  identical across N randomised row orders
```

The first says the refactor changes nothing. The second says per-widget
override still works. The third says a brand change is complete. The fourth
says the EAV row order does not matter. A failure on any of them means do not
ship.

## 6. Audit

```
python3 audit.py
```

Reports hop depth, roles nothing references, and whether the neutral ramp is
monotonic. Not pass/fail — it is the list to take to design.

## Then

`full.eav.json` is the seed for the CMS: `attribute`, `value`, `layer`,
`editable`. Import it, wire `../eav-rules.py` into save, and the structure is
enforced rather than agreed.

Ship nothing from the parent directory — see `../DO-NOT-SHIP.md`.

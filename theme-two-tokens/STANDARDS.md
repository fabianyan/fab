# Token standards for Vulcan themes

Four rules. Each one is checked by `verify.py` or `brand.py`, so none of them
depends on remembering.

## 1. A colour is written down once

A hex code appears in `1-palette.css` and nowhere else. Today `#ca22da` is
written in four places and `#060606` in five; changing the tertiary brand
colour means finding all seven names that carry it or its states. If a colour
needs a second name, that name is a **role**, and a role holds a `var()`, never
a hex.

## 2. Components read roles, not the palette

`--v-role-action-tertiary` says what a colour is *for*. `--v-brand-tertiary`
says what it *is*. A component that reads the palette directly cannot be
re-skinned without editing the component.

The one exception is the neutral ramp: `--v-neutral-000` … `--v-neutral-975`
is a scale, not a brand decision, and reading a step directly is fine.
`verify.py` fails on any other direct read.

## 3. The brand file is the only per-brand file

`0-brand-*.css` holds 15 values. Everything downstream is shared. A new brand
supplies four colours and two families and gets a working theme; hover and
active derive from the default with `color-mix()`, and any derived step can be
overridden by writing it out. theme-two overrides all of them, because its
steps were picked by eye — that is the point. **The derivation is a floor, not
a ceiling.**

## 4. No two palette colours within ΔE 3 unless someone says why

`#131313` and `#131314` are one colour with two names. `135%`, `136%` and
`137%` line height are one line height with three names. Both are what happens
when a value is chosen per component instead of taken from a scale.

New values go through the scale first. If the scale genuinely has no step that
works, add a step — and then it is available to everyone.

## The contrast gate

Run before shipping a brand. Current theme-two:

| pair | ratio | |
|---|---:|---|
| label on primary | 15.27 | pass |
| label on secondary | 4.53 | pass |
| **label on tertiary** | **4.42** | **fails AA for body text** |
| **label on subscribe** | **3.34** | **large text only** |
| **disabled label** | **3.28** | **large text only** |

Tertiary misses AA by 0.081. The nearest colour that clears 4.5:1 is `#c820d9`
— ΔE 0.61 from today's `#ca22da`, below the threshold at which anyone can see
a difference. Searched, not guessed: `brand.py` reports it.

## Shape: one `:root`, generated from EAV rows

The scheme stays a single `:root` block, exactly as today. There is no load
order and no build step, because there are no files — `layer` is a column on
the row:

```
entity     attribute                     value                    layer      editable
theme-two  --v-brand-tertiary            #ca22da                  brand      true
theme-two  --v-role-action-tertiary      var(--v-brand-tertiary)  role       false
theme-two  --v-palette-accent-highlight  var(--v-role-highlight)  alias      false
theme-two  --v-palette-nav-list-rgb      0, 0, 0                  exception  false
```

242 rows: 15 brand, 21 palette, 30 role, 25 scale, 148 alias, 3 exception.
A designer is shown the 15 marked `editable`.

**Row order does not matter.** Custom properties resolve at computed-value
time, so a `var()` pointing at a name declared further down resolves exactly
like one pointing up. `eav-test.js` shuffles all 242 rows 25 ways in Chrome and
checks every one of the 153 names still computes to the value the live site
serves. That is the property an EAV representation needs, and it holds.

Every stylesheet keeps reading the names it reads today. Nothing has to be
migrated for this to ship.

## Enforcement moves to save time

This is what EAV costs. A file layout enforces the layering by load order; a
flat table enforces nothing. So each rule above becomes a check that runs when
a row is saved — `eav-rules.py` reads the rows and nothing else, so it ports to
whatever the CMS saves with.

It catches all seven ways a row can break the system, and `eav-rules-test.py`
breaks the rows on purpose to prove it: a hex typed into a role row, a colour
given a second palette name, a component reading the palette instead of a role,
a role pointing at a name nothing defines, an `rgb` exception turned into a hex
or drifted off its colour, and a cycle between two roles.

The ΔE rule is a warning, not a failure: it asks for a sentence saying the two
colours are meant to differ.

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

## Load order

```
0-brand-theme-two.css   15 values — the only per-brand file
1-palette.css           34 colours, each named once
2-roles.css             30 roles: what a colour means
3-type.css              12 sizes + 13 line heights
4-aliases.css           150 names theme-two ships today, repointed
5-exceptions.css        3 rgb triples — delete once consumers use color-mix()
```

Every stylesheet keeps reading the names it reads today. Nothing has to be
migrated for this to ship.

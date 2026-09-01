# Merge candidates — these change pixels, so they need design sign-off

Everything in `1-`…`5-` is a pure refactor: 153/153 tokens resolve to the
value theme-two ships today. The list below is different. Each line is two
values a person cannot tell apart, kept as separate decisions. Merging them
is a judgement call, not a safe rename.

## Colours no one can distinguish

CIE76 ΔE — below 1.0 is invisible on any screen, below 2.3 is the
"just noticeable difference" under laboratory conditions.

| ΔE | | | verdict |
|---:|---|---|---|
| 0.64 | `accent-footer` #131313 | `accent-hover-primary` #131314 | invisible — merge |
| 1.21 | `neutral-150` #efecec | `neutral-225` #ebebeb | indistinguishable in use |
| 1.63 | `accent-border-strong` #202022 | `accent-hover-dark` #222326 | indistinguishable in use |
| 1.65 | `accent-header` #000000 | `accent-inverse` #060606 | indistinguishable in use |
| 1.65 | `accent-header` #000000 | `language-selector-rgb` 6, 6, 6 | indistinguishable in use |
| 1.65 | `accent-inverse` #060606 | `nav-list-rgb` 0, 0, 0 | indistinguishable in use |
| 1.65 | `language-selector-rgb` 6, 6, 6 | `nav-list-rgb` 0, 0, 0 | indistinguishable in use |
| 1.78 | `neutral-750` #1b1e1f | `neutral-825` #1c1c1c | indistinguishable in use |
| 2.07 | `accent-text-inverse` #ffffff | `neutral-075` #f9f9f9 | indistinguishable in use |
| 2.09 | `accent-border-strong` #202022 | `accent-search` #232020 | indistinguishable in use |
| 2.09 | `accent-border-strong` #202022 | `language-selector-footer-rgb` 35, 32, 32 | indistinguishable in use |
| 2.12 | `accent-border-strong` #202022 | `neutral-750` #1b1e1f | indistinguishable in use |
| 2.38 | `neutral-300` #cfcfcf | `neutral-375` #cbccd0 | very close |
| 2.51 | `accent-border-strong` #202022 | `neutral-825` #1c1c1c | very close |
| 2.68 | `accent-disabled` #8e8e8e | `neutral-525` #959595 | very close |
| 2.76 | `accent-search` #232020 | `neutral-825` #1c1c1c | very close |
| 2.76 | `language-selector-footer-rgb` 35, 32, 32 | `neutral-825` #1c1c1c | very close |
| 2.91 | `accent-hover-dark` #222326 | `accent-hover-icon` #272727 | very close |

## Type: 12 sizes and 13 line heights for 26 styles

A scale with steps this fine is not a scale — it is a record of individual
decisions. The clusters below are within 1–2% of each other, which is under
half a pixel at these sizes.

**Line heights, sorted:** `120%`, `125%`, `130%`, `133%`, `135%`, `136%`, `137%`, `138.5%`, `140%`, `147%`, `150%`, `176%`, `normal`

- `135%` `136%` `137%` — three values spanning 0.3px at 16px. One value.
- `147%` `150%` — 0.5px apart at 16px.
- `120%` `125%` — the only genuinely distinct short pair.

**Sizes, sorted:** `10px`, `12px`, `14px`, `16px`, `17px`, `18px`, `20px`, `22px`, `24px`, `30px`, `40px`, `45px`

- `16px` `17px` `18px` — 17px appears 3 times and is 1px from both neighbours.
- `20px` `22px` — 2px apart, 4 and 2 uses.

## Styles that are already the same style

Identical size, line height and weight under two names:

- **16px / 176% / 700** → `normal-link-mobile`, `link-list`
- **18px / 140% / 700** → `normal-link-desktop`, `action-label-desktop`

## What a brand has to edit today to move one colour

| brand colour | names that must change together |
|---|---:|
| primary | **3** |
| secondary | **5** |
| tertiary | **7** |
| subscribe | **3** |

After the refactor: **1** each.


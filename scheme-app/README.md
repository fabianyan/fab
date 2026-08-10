# Vulcan Scheme Editor

A hosted page for designers and engineers: paste a site URL, it loads the
**real page** next to a **live scheme-variable editor**. Editing a variable
repaints the real page instantly. No install, no terminal for end users.

## Why a backend exists

A static HTML file can't fetch other origins (CORS), and Vulcan injects
scheme values at runtime — static CSS doesn't contain the resolved values.
So a serverless function renders the target page with headless Chromium,
reads the resolved `--scheme-*` variables off `:root`, and returns the
page's HTML/CSS plus those variables.

## Project structure

```
public/index.html               frontend: URL box, "Basic Auth", editor, live iframe
lib/capture.js                  the capture itself: POST {url,user,pass,device} -> {root, authored, css, body, base, pageUrl, device, pageFont, schemeNames, varCount, schemeCount}
api/capture.js                  Vercel adapter (req/res)
netlify/functions/capture.js    Netlify adapter (event/handler)
vercel.json                     outputDirectory=public, 60s maxDuration, production install skips devDependencies
netlify.toml                    publish=public, functions dir, esbuild, chromium included_files, /api/* redirect
package.json                    deps: @sparticuz/chromium, puppeteer-core
```

The browser work sits in `lib/capture.js` and each platform gets a thin
adapter, so the two hosts run the same code rather than two copies that drift.
The frontend posts to **`/api/capture`** — where Vercel serves functions from —
and `netlify.toml` redirects `/api/*` onto the Netlify function, so one path
works on both and the page never has to know where it is running.

## Updating the live app

The deployed site is built from **`fabianyan/schema-editor`, branch `main`**.
Push to `main` and Vercel builds and publishes it; there is no other step and
no manual deploy.

To check which build a browser is actually showing, read the tag beside the
title in the header (`vercel-v34`). It is bumped with every change, so a stale
tag means a cached page rather than a failed deploy — reload.

To change something:

```bash
git clone https://github.com/fabianyan/schema-editor
cd schema-editor && npm install
npm run dev            # local, same code as production
# edit public/index.html or lib/capture.js, try it locally
git commit -am "what changed" && git push      # this deploys
```

To undo a bad deploy, either promote the previous deployment in the Vercel
dashboard (instant, no build) or `git revert` and push (slower, but keeps the
repo and the live site telling the same story).

The same app also lives in `fabianyan/fab` under `scheme-app/`, kept in step by
hand. Nothing deploys from there — it is a copy, and the live one is
`schema-editor`.

## Local development

```bash
npm install
npm run dev        # runs `netlify dev`
```

Open the local URL, paste a page (e.g. `www.casino.com/zh/` — the
`https://` is optional), click **Load real page**. The editor should populate with the page's
`--scheme-*` variables grouped by family; editing a value should repaint the
iframe immediately.

## How it works

1. Frontend POSTs `{ url, user?, pass? }` to `/.netlify/functions/capture`.
2. The function launches Chromium (`@sparticuz/chromium` + `puppeteer-core`),
   optionally authenticates via `page.authenticate` (credentials are used
   in-request only, never stored), and navigates to the URL.
3. It gathers every custom property declared in a rule that reaches `:root`,
   plus every `--scheme-*` name referenced anywhere in the page's
   stylesheets or set inline on `:root`, reads each one off the computed
   style of `document.documentElement`, and keeps those that resolve to a
   value. Names have to be collected this way because a computed style's
   indexed list contains only standard properties — iterating
   `getComputedStyle(el)` never yields a custom property, even though
   `getPropertyValue('--x')` resolves it. It also collects any
   `data-color-scheme` names and captures the post-JS `<body>` HTML with
   `<script>` tags stripped.
4. It fetches the page's linked stylesheets and strips their `:root { ... }`
   blocks (the resolved values are already captured in step 3 — this avoids
   the iframe re-deriving stale/default values from the raw CSS). Two rewrites
   keep the typefaces alive through that step, and both are load-bearing: a
   sheet's relative `url()`s are made absolute against the sheet, since the
   preview resolves everything against the *page* and would otherwise look for
   `../fonts/lato.woff2` in the wrong directory; and every `@import` is lifted
   to the front of the concatenation, because `@import` is only honoured at the
   start of a stylesheet and a site that loads its typeface that way would
   otherwise render in a fallback face with no error anywhere. The panel
   re-declares those imports as stylesheet links of its own, so its specimens
   use the real face too.
5. The frontend renders the body + stripped CSS inside a sandboxed
   (`allow-same-origin`, no scripts) `<iframe srcdoc>`, with a `<base href>`
   pointing at the page's origin so relative assets resolve. Editing a
   variable calls `iframe.contentDocument.documentElement.style.setProperty`
   directly for an instant repaint (no full reload).
6. **Export CSS…** offers the edit as a changed-only `:root` block or the full
   one, each copyable or downloadable as a `.css` file. Applying a scheme
   happens outside this tool, so handing over raw CSS is where its job ends.

## What counts as a variable

Not only the `--scheme-*` namespace. A scheme rests on the page's own tokens:
the family lives in `--font-base`, and a scheme token is written against them —
`--scheme-typography-h1-fontWeight-m: var(--font-weight-bold)`, itself
`var(--fw-bold)`. Capturing only the scheme namespace cost three things:

- the font family could not be edited at all, because nothing represented it;
- that two-hop weight chain collapsed to the literal `700`, since a reference to
  an uncaptured variable has to fall back to its resolved value — so editing
  weight could not cascade;
- and because `:root` blocks are stripped from the returned CSS, the preview
  lost `--font-base` entirely and rendered the page, and every type specimen,
  in a fallback face.

So every custom property that reaches `:root` is captured, page-level ones
included. They get ordinary editable rows grouped under their own first
segment (`font`, `fw`), and the full name on each row says which namespace a
value belongs to. Nothing is invented: a name that resolves to no value is
dropped, and a reference to an undefined variable cannot create an entry.

The status line counts them separately — `7 page-level, 10 scheme` — so it is
clear the tokens the typography points at actually arrived.

## The editor panel

The panel is the scheme's spec sheet as well as its editor. Each row carries a
swatch, the token's own name in bold, the complete variable name beneath it,
and the editable value — so nothing is truncated away and two tokens whose
names differ only in a final segment cannot read as duplicates. Clicking the
variable name copies it; clicking the bold name jumps to the row from the
inspector.

**Swatch legibility.** A 20px square on one fixed background cannot show this
kind of palette: `#060606` disappears on a dark panel and `#FFFFFF` on a light
one, and translucent values look opaque. Swatches are therefore larger, sit on
a checkerboard so anything semi-transparent reads as such, and carry a two-tone
ring — light inside, dark outside — that holds an edge against both extremes.
The colour is painted on an inner element so it never covers the checkerboard.
A value stored as a bare channel triplet (`6, 6, 6`, meant for
`rgba(var(--x), .4)`) is a colour too, so it gets a swatch painted through that
same `rgb()` wrapper; picking a colour for one writes a triplet back rather
than a hex, which would otherwise break the `rgba()` around it.
A **Dark | Light** backdrop toggle flips the panel itself, because no single
background suits every value. Rows whose value is not a colour show no swatch
rather than an empty square.

**Type specimens.** Typography tokens arrive one property at a time —
`…-h1-fontSize-m`, `…-h1-lineHeight-m`, `…-h1-fontWeight-m` — and say almost
nothing read individually. The breakpoint suffix is split off as a *variant* of
a style rather than a style of its own, so each style (h1, h2, buttonBig) shows
its sizes together, largest first, as a scale. Suffixes carry step numbers in
practice (`-s`, `-s2`, `-s3`, `-m2`, `-m3`); those count as breakpoints too, or
`normal-fontSize-s2` would fold the number into the name and invent a style
called `normal-s2` sitting apart from the scale it belongs to. The chip keeps
the number (`S2`) so the steps are told apart.

Only `--scheme-*` typography tokens form specimens. A page token like
`--font-weight-bold` contains "font-weight" as well, and reading it as a
typography set would conjure a style named "bold" out of a single weight.

Each variant is a line of text rendered at that exact size, weight, line height
and face, tagged with a breakpoint chip and the numbers (`45px / 137% / 700`).
The specimen leads: it is one line clipped with an ellipsis so a 45px style
still shows its true size, and the tokens behind it stay collapsed until you
click the specimen, at which point they appear as ordinary editable rows.
Editing one updates the specimen immediately. `h1`…`h6` sort numerically ahead
of named styles.

Property names are matched in either spelling and anywhere in the token, since
real names put a camelCase property before the breakpoint
(`buttonBig-fontSize-desktop`) rather than a kebab-case one at the end.
Matching only the latter found no sets at all on a real scheme, leaving a flat
wall of near-identical rows.

**A font row is named after its font, not its token.** `--font-lato` used to
read **lato** whatever it held, so changing it to Tahoma left the one label
that should answer "which font is this?" answering with the old one. The row
now shows the family it currently holds, drawn in that face, with an `Aa`
specimen in the square the colour rows use and the field itself set in the same
face. The full variable name stays on the line beneath — that is what tells two
font slots apart, and what gets exported.

**Changing the family.** A row holding a family (`"Lato", sans-serif`) gets a
list of the families the capture found — the stacks the scheme already uses and
the faces the page loads through `@font-face`. Whole stacks are offered rather
than bare names, so picking one keeps its fallbacks. The field stays free text,
so any CSS value can be typed; the list is a shortcut, not a restriction. Rows
holding a size or a weight get no list.

The suggestions are deliberately limited to what the page loads. A font this
tool made up would render here and nowhere else: the site has no `@font-face`
or `@import` for it, so it would fall back to whatever happens to be installed
on the next person's machine.

**Trying a font the site does not have.** A missing family's row offers
**Load from Google**, which fetches that family from Google Fonts into both the
preview and the panel, so a face the site has never carried can still be judged
on the real page. It is a button, never automatic: it calls a third party, and
it shows you something the site cannot render yet.

Above the list, **Load N fonts from Google** does the whole set at once, which
is the usual case: a scheme names twenty faces, the page loads two, and
choosing between them one click at a time is twenty clicks for one decision.
The count is what is actually missing — families the page already renders are
not re-fetched — and the tooltip lists them. Families Google does not have are
reported rather than passed over silently (`4 families loaded · 1 not on Google
Fonts`), and the button stays, showing only what is still missing.

Fetched faces are *asked for* before the panel re-measures. Declaring
`@font-face` does not fetch anything — a browser loads a face when something
needs it — so measuring straight after injecting still sees the fallback, and
every row would flash "not loaded" until some later refresh caught up.

That caveat travels with the work rather than being left as a surprise. The
status line says *preview only*, and **Export CSS** puts the matching
`@import` above the `:root` block with a comment saying it has to be added too
— without it the exported variables fall straight back to the previous face on
the live site. Fetched families survive a recapture, since they are a choice
you made rather than anything belonging to the captured page.

The weight axis (`:wght@100..900`) is requested first so weight edits show,
and dropped on a second attempt, because a family with only static weights
answers 400 to a range.

Type one anyway and the row says **not loaded**. This is the one edit that
changes the CSS and nothing else — the browser quietly falls through to the
next family in the stack, so the field reads `"Henny Penny"` while the page
keeps its old face and the tool looks broken. Availability is *measured*, not
asked: `FontFaceSet.check()` answers true for a family nobody defines, because
the text can indeed be drawn — in the fallback. So a fixed string is rendered
in `"X", <generic>` and in `<generic>` alone and the widths compared, against
three generics in case the face metric-matches one. A face the page declares
but has not fetched yet measures like its fallback, so it is requested through
`fonts.load()` and re-measured before being called missing.

Because most typography sets declare a size and weight but no family, their
specimens fall back to the page's own — read live from the preview, so editing
`--font-base` restyles the specimens as well as the page. Reading it once at
capture time left every specimen in the old face while the preview beside it
had already changed.

Everything a specimen displays comes from the capture, never from this app:
where a variant declares no family or size, the fallback is the captured page's
own body value, and the page's `@font-face` rules are copied in (with relative
`url()`s rewritten to absolute) so specimens render in the site's real
typeface. Absent both, the property is left unset rather than invented.

Every captured variable gets an editable row, including the tokens behind a
type specimen — this is an editing tool, so nothing is read-only and nothing is
hidden behind an expander by default. Clicking a specimen collapses its tokens
when you want to compare sizes without the noise.

Full names remain the keys in state, the `data-var` attributes, and what
**Export :root** writes, so exported declarations stay complete and
paste-ready. Filtering still matches the full name, so `scheme-typography`
works as a search.

## When editing a variable changes nothing

Two different reasons, and the panel now names both, because otherwise the tool
just looks broken.

**Nothing references it.** Every row carries a usage count — `12×`, or an
**unused** tag — counted from the declarations in the captured CSS. A scheme
routinely defines a shelf of font families where the design wires up two;
editing one of the rest cannot move the page, and the count says so before you
spend time on it.

**Its value was copied, not referenced.** This is the common one, and "unused"
would be a misleading word for it. A scheme built through a CMS often defines
`--scheme-colors-color-primary` and then writes the *same literal* into every
CTA and component token rather than `var(--scheme-colors-color-primary)` — the
derivation happened before the CSS existed. So the general colour genuinely has
no reference anywhere in the page's CSS, while plainly being the colour you see.
Those rows read **shared ×N** instead, naming how many tokens hold the same
value.

**Editing a main colour carries its own tokens with it.** Change
`--scheme-colors-color-primary` and every token that is *named for that role
and holds the identical value* — `--scheme-colors-cta-primary-default`,
`--scheme-components-button-primary-text` — follows immediately, no prompt.
That is the brand colour restated under another name, not a coincidence.

Both tests have to pass, and each one alone is wrong. The name alone would drag
`background-primary` (a near-white) along with the brand orange. The value alone
would drag every unrelated token that happens to be `#FFFFFF`. Names are matched
by word with camelCase split apart, so `primaryDark` counts as carrying
"primary".

Shades *derived* from the colour rather than equal to it — a hover `#FF5421`
against a default `#FF6B00` — are deliberately left where they are. Nothing in
the capture says how that shade was computed, and guessing would invent a
relationship the CSS never stated.

Anything else that merely shared the old value is offered instead: **Also
update N tokens that were #FF6B00**, with the exact list in its tooltip.
Accept and they move too — and stay tied to that colour, so the next edit
carries them without asking again. Tokens you set by hand are never
overwritten: that was a decision. **Reset all** undoes the lot.

Where a real `var()` chain exists it still cascades on its own, with no offer
needed — see below.

**The value is written into the rule.** A title whose CSS says
`font-family: "Kanit", sans-serif` outright has no variable to edit. Clicking it
now shows a **Hard-coded — no variable** section listing those declarations
(family, size, weight, line-height, colour, background-colour) for the element
and for the ancestors it inherits type from. Nothing there is editable — that
is the point: it explains why the family variable left this title alone, and
sends the change to the stylesheet rather than the scheme.

A family is only reported as hard-coded when the element is genuinely rendering
in it: the browser has already resolved the whole cascade, so its computed value
decides which of several matching rules won. Guessing from selectors alone
would mislabel a title that a more specific rule styles through a variable.

The nearest declaration of a property wins, so a family named again on every
ancestor is listed once. Literal declarations are indexed separately from
variable ones, since the "inside this element" scope tests every indexed rule
against a `querySelectorAll` and folding thousands of hard-coded declarations
into that list would slow every inspection down.

## Browsing between pages

Clicking a link in the preview loads that page: the click is intercepted and
turned into a fresh capture of the link's URL, the same path as typing it in
the box. Shift-click a link to inspect its styling instead of following it,
and hover any link to see where it goes.

**A link to this same page is not navigation.** A button-styled anchor like
`https://www.casino.com/#Guides` resolves to the document already on screen, so
capturing it would spend ten seconds rebuilding that page and throw the
selection away — exactly when someone clicked a button *because* they wanted to
see what styles it. Those clicks inspect instead, and still scroll the preview
to the anchor, since the default scroll was suppressed along with every other
navigation. Hovering one says `↓ jumps within this page` rather than showing a
URL, so it does not read as a dead link.

That interception is unconditional, and has to be. The captured body holds
the site's real `<a href>` links, and a sandboxed iframe is still permitted
to navigate *itself* — so an un-intercepted click loads the live site
cross-origin. The preview would then be showing a page this app can neither
read nor identify, while the editor still described the previous one, making
recapture look like it jumps backwards. Form submissions are blocked for the
same reason. If the preview does end up on an unreadable document, the
status bar says so rather than leaving the editor silently out of sync.

**↻ Recapture** re-captures whatever page the preview is currently showing,
for when the site has changed or you want to re-pull it with different
credentials. It deliberately ignores the URL box and uses the previewed
page's own URL, so typing a different address without loading it cannot
divert the recapture; its tooltip names the exact target.

The captured URL is the one the browser landed on, not the one requested,
so a host that redirects (`casino.com` → `casino.com/zh/`) reports its real
destination — which is what recapture re-pulls and what relative links
resolve against.

Any edits you have made are carried onto the next page, so a scheme in
progress can be checked across several pages without re-entering values —
the status line reports how many were kept. **Reset all** clears them.

Relative links resolve against the captured page's own URL rather than just
its origin, so a `games/` link on `/zh/` correctly loads `/zh/games/`.

## Desktop / mobile

The **Desktop | Mobile** toggle switches the preview between a 1440px frame
and a 390×844 phone frame. Narrowing the frame is what re-runs the page's
own media queries, so the mobile view is the real responsive layout rather
than a scaled picture of the desktop one.

Captures are also *made* as the chosen device: the function sets a matching
viewport and, for mobile, an iPhone user-agent, because sites can serve
different markup and assets to phones rather than only different CSS. The
device is remembered and used for every subsequent capture.

Switching the toggle only resizes; it does not re-fetch, since a capture
takes seconds. When the width no longer matches what was captured, the
status bar says so and points at **↻ Recapture**.

Two limits worth knowing:

- `:root` blocks are stripped from the fetched CSS, **including ones inside
  media queries**, because the resolved values are captured separately and
  stale defaults would otherwise override them. So a site that redefines
  `--scheme-*` per breakpoint will not show those differences from the width
  toggle alone — recapture at that device to get them.
- The captured markup is fixed at capture time, so a site that serves a
  different DOM to phones only shows it after a recapture as mobile.

## Inspect mode

Inspect is on by default: hovering the preview outlines elements, and
clicking one opens a panel showing every captured variable that styles
it — `font-family: var(--font-titles)` included, since that is exactly the
declaration someone clicking a heading is looking for. Each variable appears as the **same editable row used in the main
list** — swatch, color picker, text field, and reset — so you can change a
value straight from the inspector and watch the page repaint. A variable
shown in both places stays in sync.

Under each row are the declarations that reference it (`background-color ·
.cta → rgb(10, 125, 51)`), so you can see which properties and selectors
it drives. Clicking the variable's name scrolls to its row in the main
list. Use **↑** to walk up to the parent element, and the **Inspect**
button to toggle the mode off.

Results are split into three scopes, because the variable painting what you
clicked is often declared nowhere near it:

- **On this element** — rules matching the element itself. This is all a
  browser's devtools shows, and on its own it is misleading: a container
  usually declares only its background and border.
- **Inherited from ancestors** — inheritable properties (`color`, the `font-*`
  family, `line-height`, and friends) set on an ancestor. Text colour is
  normally set once high up, so without this scope an element full of
  coloured text appears to have no colour variable at all. Each row names the
  ancestor it came from (`↑ div.page-wrap`) and shows the value as it
  resolves *on the selected element*, which is the effective one.
- **Inside this element** — rules matching descendants, matched with
  `querySelectorAll` against the subtree. A `×N` suffix shows how many
  elements a rule hit. This is where a card's button colour, heading and star
  rating live.

A variable is listed once, in the first scope it appears in, so the sections
read as a progression: set here, handed down to here, used somewhere below
here.

To keep that fast on real pages, every declaration referencing a
`--scheme-*` variable is indexed once per capture; inspecting then filters
that short list instead of re-walking every stylesheet per element.

Declarations are read from the authored text of each matching rule rather
than from CSSOM's expanded longhands. That matters: CSSOM expands
`background: var(--scheme-x)` into `background-image`, `background-color`
and friends, whose values read back as empty strings when they came from a
shorthand containing `var()` — iterating properties therefore misses every
shorthand declaration. Parsing the rule text also keeps the property name
the author wrote, so one `border-color` shows up once instead of as four
`border-*-color` longhands.

Pseudo-element rules (`.btn::before`) are matched against their base
selector so their variables still surface; the panel shows the full
selector so you can tell.

## Deploying

### Vercel (current deployment)

Connect the repo; every push to `main` deploys. `vercel.json` carries the
settings that matter:

- `outputDirectory: "public"` — the static page.
- `maxDuration: 60` and `memory: 1769` on `api/capture.js`. The default 10s is
  not enough: Chromium has to cold-start *and* load a real page. 60s is the cap
  on the Hobby plan.
- `installCommand: "npm install --omit=dev"` — the dev dependencies are
  `netlify-cli` and full `puppeteer`, and puppeteer's postinstall downloads a
  ~150 MB Chromium the deployed function never uses.

If the repo holds more than this app (as `fabianyan/fab` does, where it lives
in `scheme-app/`), set the project's **Root Directory** to that folder in the
Vercel dashboard — it is a project setting, not something `vercel.json` can
express.

`vercel dev` runs the function on your own machine, where the Lambda Chromium
binary cannot execute, so it takes the same local-dev path as `netlify dev`.

**One Vercel-specific fix worth knowing about.** `@sparticuz/chromium` ships
Chromium's shared libraries (libnss3 and friends) as a separate archive, and
only unpacks them — and points `LD_LIBRARY_PATH` at them — when it believes it
is inside a Lambda container, which it decides from `AWS_EXECUTION_ENV` or
`AWS_LAMBDA_JS_RUNTIME`. Vercel's functions *do* run on Lambda but expose
neither, so the archive was never unpacked and the binary died on launch with
`libnss3.so: cannot open shared object file`. Setting `AWS_LAMBDA_JS_RUNTIME`
ourselves fixes it, but it must be set **before** the module is required, since
both the unpacking and the `LD_LIBRARY_PATH` assignment happen at require time.
Which archive is right follows the OS behind the runtime, and the Node version
identifies it: 20 and later are Amazon Linux 2023, earlier ones Amazon Linux 2.
A host that already sets either variable knows better and is left alone.

### Netlify

Also still supported: `netlify.toml` sets `publish = "public"` and
`functions = "netlify/functions"`, and redirects `/api/*` onto the function so
the same frontend works. Netlify's free/starter tiers cap synchronous function
execution below 30s regardless of the `netlify.toml` setting — if Chromium
cold-start + page load exceeds your plan's real limit, you'll need a paid tier
or a lighter wait strategy.

## Known unverified items (do these first after deploying)

1. ~~**Chromium actually running on the host.**~~ **Confirmed working on
   Vercel** — captures return real variables from the deployed function. It
   took the `AWS_LAMBDA_JS_RUNTIME` fix described under Deploying. If it ever
   regresses on a bundle-size limit rather than a library one, the fallback is
   `@sparticuz/chromium-min` with the binary fetched from a release URL.
2. **Cold-start time / timeout.** Chromium boot + `networkidle2` may
   approach the platform's real function timeout on heavier pages. May need
   a lighter wait strategy (e.g. `domcontentloaded` + a short fixed delay)
   if `networkidle2` is too slow.
3. **Large-page response size.** Real pages can be 1–2 MB of HTML+CSS JSON.
   Confirm this is acceptable through the function response; consider gzip
   or trimming to main content if it's slow.
4. **Auth edge cases.** Verify `page.authenticate` works through the
   deployed function against a real basic-auth-protected dev site, and that
   the target's IP allowlist (if any) permits Netlify's egress IPs.

## Open decisions (product/security, not code)

1. **Hosting & ownership.** Which Netlify team/account does this deploy
   under, and which engineer owns the URL + maintenance?
2. **Dev-site credentials on a shared URL.** The app forwards user/pass
   per-request and never stores them, but a hosted URL that can reach
   internal/dev sites is a security call. Decide before sharing widely:
   restrict access to the app itself (SSO / Netlify password / IP
   allowlist), and/or how dev credentials are handled.

## Nice-to-haves (not required for MVP)

- Multi-page / index of captured schemes.
- Cache captures to cut repeat cold-starts.
- Contrast (WCAG) check on text/background pairs.
- Flag in the UI when a component's dedicated variable is undefined (known
  New-scheme bug: New defines general `--scheme-colors-*` colors but not
  the singular `--scheme-color-*` component-layer variable many components
  actually reference).

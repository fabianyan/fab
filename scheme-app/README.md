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
netlify/functions/capture.js    POST {url,user,pass,device} -> {root, css, body, base, pageUrl, device, pageFont, schemeNames, varCount}
netlify.toml                    publish=public, functions dir, esbuild, chromium included_files, 30s timeout
package.json                    deps: @sparticuz/chromium, puppeteer-core
```

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
3. It gathers every `--scheme-*` name referenced anywhere in the page's
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
   the iframe re-deriving stale/default values from the raw CSS).
5. The frontend renders the body + stripped CSS inside a sandboxed
   (`allow-same-origin`, no scripts) `<iframe srcdoc>`, with a `<base href>`
   pointing at the page's origin so relative assets resolve. Editing a
   variable calls `iframe.contentDocument.documentElement.style.setProperty`
   directly for an instant repaint (no full reload).
6. **Export :root** dumps the current (possibly edited) variable set as a
   `:root { ... }` block you can copy and hand to engineering.

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
A **Dark | Light** backdrop toggle flips the panel itself, because no single
background suits every value. Rows whose value is not a colour show no swatch
rather than an empty square.

**Type specimens.** Typography tokens arrive one property at a time —
`…-h1-fontSize-m`, `…-h1-lineHeight-m`, `…-h1-fontWeight-m` — and say almost
nothing read individually. The breakpoint suffix is split off as a *variant* of
a style rather than a style of its own, so each style (h1, h2, buttonBig) shows
its sizes together, largest first, as a scale.

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

Everything a specimen displays comes from the capture, never from this app:
where a variant declares no family or size, the fallback is the captured page's
own body value, and the page's `@font-face` rules are copied in (with relative
`url()`s rewritten to absolute) so specimens render in the site's real
typeface. Absent both, the property is left unset rather than invented.

Full names remain the keys in state, the `data-var` attributes, and what
**Export :root** writes, so exported declarations stay complete and
paste-ready. Filtering still matches the full name, so `scheme-typography`
works as a search.

## Browsing between pages

Clicking a link in the preview loads that page: the click is intercepted and
turned into a fresh capture of the link's URL, the same path as typing it in
the box. Shift-click a link to inspect its styling instead of following it,
and hover any link to see where it goes.

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
clicking one opens a panel showing every `--scheme-*` variable that styles
it. Each variable appears as the **same editable row used in the main
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

Deploy this repo as a Netlify site (`netlify.toml` sets
`publish = "public"` and `functions = "netlify/functions"`). Netlify's
free/starter tiers cap synchronous function execution below 30s regardless
of the `netlify.toml` setting — if Chromium cold-start + page load exceeds
your plan's real limit, you'll need a paid tier or a lighter wait strategy.

## Known unverified items (do these first after deploying)

1. **Chromium actually running on Netlify.** The `@sparticuz/chromium` +
   `puppeteer-core` combo and the `included_files`/timeout config are
   standard but untested against a live deployment. Confirm `varCount > 0`
   against a real URL; expect to tweak chromium version pinning, function
   memory, or bundling if it fails.
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

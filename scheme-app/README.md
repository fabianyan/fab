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
scheme-app/
  public/index.html               frontend: URL box, "+ Login", editor, live iframe
  netlify/functions/capture.js     POST {url,user,pass} -> {root, css, body, base, schemeNames, varCount}
  netlify.toml                     publish=public, functions dir, esbuild, chromium included_files, 30s timeout
  package.json                     deps: @sparticuz/chromium, puppeteer-core
```

## Local development

```bash
cd scheme-app
npm install
npm run dev        # runs `netlify dev`
```

Open the local URL, paste a page (e.g. `https://www.casino.com/zh/`), click
**Load real page**. The editor should populate with the page's
`--scheme-*` variables grouped by family; editing a value should repaint the
iframe immediately.

## How it works

1. Frontend POSTs `{ url, user?, pass? }` to `/.netlify/functions/capture`.
2. The function launches Chromium (`@sparticuz/chromium` + `puppeteer-core`),
   optionally authenticates via `page.authenticate` (credentials are used
   in-request only, never stored), and navigates to the URL.
3. It reads every computed `--scheme-*` custom property off
   `document.documentElement`, collects any `data-color-scheme` names on the
   page, and captures the post-JS `<body>` HTML with `<script>` tags
   stripped.
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

## Deploying

Deploy the `scheme-app/` directory as its own Netlify site (`netlify.toml`
sets `publish = "public"` and `functions = "netlify/functions"`). Netlify's
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

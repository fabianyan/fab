# Vulcan API Explorer

A small full-stack tool for interactively querying the Vulcan CMS admin API,
built from `Vulcan CMS — API Flow Documentation` (the HAR-verified endpoint doc).

It covers:

1. **Pick a site, a resource, and a method** — a catalog of every documented
   entity type and endpoint (auth, sites, entities CRUD/publish/status/delete,
   media, networks, revalidate), with the real HTTP method and path.
2. **See its parameters** — path/query/body fields are rendered from the doc,
   including which are required, JSON-string-in-JSON quirks, the widgets UUID
   coupling rule, and a confidence badge (HAR-verified / partially documented
   / inferred) so you know what to double-check against the real API.
3. **Save responses and reuse their values as parameter inputs** — e.g. save
   a Sites or Entities list response, pick which field is the key (usually
   `id`) and which is the label (e.g. `name` or `values.internal_name`), then
   use the 🔗 link button on any id-like field elsewhere to pick that value
   instead of typing it.
4. **Call the API and see/download the response** — pretty-printed JSON,
   status + timing, "Download JSON".
5. **Stays connected for as long as you're in the app** — the JWT (300s
   lifetime, per the doc) is refreshed proactively every ~4 minutes and
   reactively on any 401, transparently, server-side. The `jwtauthorization`
   header and `x-site-id` site token are never exposed to the browser.
6. **Cross-entity / cross-site DB query** — search for an attribute or
   property value (dot-notation path, e.g.
   `values.brand_features.brand_features_local[].features_title`) on one site
   or across the whole CMS, or specifically find every page embedding a given
   widget type ("widget usage").

## Running it

```bash
npm install
npm start            # http://localhost:3100
```

Open the app, click **Connect / Log in**, and enter the real admin base URL
(e.g. `https://staging-admin.clickto.bet`) plus your credentials. If 2FA is
enabled you'll be prompted for the 6-digit code next (see "Open questions"
below — there's no programmatic 2FA bypass here, this just wires up the
documented flow).

Nothing is hardcoded to one environment — base URL, site tokens, and entity
IDs are all resolved/entered at runtime, per the doc's own guidance that
these are environment-specific.

### Architecture

The browser never talks to Vulcan directly. Everything proxies through this
app's own Express server, which:

- holds the session (JWT + refresh token + per-site token cache) server-side,
  keyed by an httpOnly cookie — the browser never sees the `jwtauthorization`
  value or site tokens;
- implements the doc's reactive refresh (401 → `/api/token/refresh` → retry
  once) and a proactive refresh timer (~every 4 min) so the connection
  survives as long as the tab is open;
- executes catalog operations generically (`POST /api/call`) — one code path
  for every entity type and endpoint, path built from the operation's
  template, headers attached based on scope (`none` / `global` / `site` /
  `site-domain` for revalidate which hits the *site's* own domain, not admin);
- runs the DB-query endpoints (`POST /api/query/attribute`,
  `POST /api/query/widget-usage`) by paging through `GET /api/entities` per
  site/entity-type and walking each entity with a small path-matcher
  (`src/jsonPath.js`) that supports `a.b[].c` array iteration.

Saved-response sets (the key/value linking feature) live in the browser's
`localStorage` — they're just remembered UI convenience, not sensitive data.

### Files

```
server.js                 entry point
src/catalog.js             the endpoint + entity-type catalog transcribed from the doc
src/jsonPath.js             dot/bracket path walker used by the DB query engine
src/sessionStore.js          in-memory session (JWT lifecycle, per-site token cache)
src/vulcanClient.js          HTTP calls to Vulcan with 401->refresh->retry-once baked in
src/queryEngine.js           cross-site/cross-entity-type attribute + widget-usage search
src/routes/*.js              auth, sites, catalog, generic call executor, query
public/*.js                  vanilla-JS UI (no build step) — explorer, saved responses, DB query tabs
mock/mock-server.js          a stand-in Vulcan API for local testing (NOT the real backend)
test/integration.test.js     end-to-end test against the mock server (`npm test`)
```

## Testing

```bash
npm test        # spins up the mock server + this app, exercises the full flow
npm run mock     # run the mock server standalone, e.g. to poke at it with curl
```

`npm test` has no real Vulcan credentials to exercise this against, so it
runs against `mock/mock-server.js` — a minimal stand-in that reproduces the
shapes and quirks called out in the doc (300s-ish JWT expiry, the 423
promotion-exclusivity rule, 2FA, hydra-style list responses) closely enough
to validate the app's *logic* (auth/refresh, generic call routing, entity
CRUD, the query engine). It is **not** a faithful clone of the real backend —
treat a green `npm test` as "the plumbing works," not "this matches
production." The UI itself was manually verified end-to-end in a real
browser (Playwright) against this mock during development, covering: login
with and without 2FA, the parameter form + widget-template helper, the
save-response → 🔗 link-picker flow, entity create/publish/revalidate, and
both DB-query modes.

Before pointing this at a real environment, sanity-check a few calls (e.g.
List sites, then List entities for a known type) against what you see in the
admin UI's network tab.

## Known gaps (inherited from the source doc)

- **2FA**: the login flow is wired up per the doc, but there's no TOTP-secret
  auto-generation — you type the 6-digit code each time, same as a human
  would.
- A few operations are marked "inferred — verify" in the UI (network
  list/get, entity list/get, entity-types list) because the doc didn't
  directly capture them in a HAR recording — the shapes are reasonable
  guesses, not confirmed.
- `entity_publish` requires the **full** entity payload (per the doc, a
  minimal body is unconfirmed) — the UI nudges you to "Get entity" first and
  paste its response in, rather than trying to reconstruct it for you.
- The DB query engine pages through `GET /api/entities` per site per entity
  type, capped at 25 pages / 5000 entities per (site, type) pair as a safety
  limit — a truncation warning is surfaced in the results if you hit it.

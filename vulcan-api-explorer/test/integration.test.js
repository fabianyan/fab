'use strict';

/**
 * End-to-end smoke test: spawns the mock Vulcan API and the explorer's own
 * server as child processes, then drives the explorer's HTTP API exactly the
 * way the browser UI does — auth (both no-2FA and 2FA paths), reactive JWT
 * refresh on 401, generic entity CRUD/publish/status/delete, the 423
 * promotion-exclusivity rule, media upload, and both DB-query flavors.
 *
 * Run: npm test
 */

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const MOCK_PORT = 4091;
const APP_PORT = 3191;
const MOCK_BASE = `http://localhost:${MOCK_PORT}`;
const APP_BASE = `http://localhost:${APP_PORT}`;

function startProcess(script, env) {
  const child = spawn(process.execPath, [script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', () => {});
  child.stderr.on('data', (d) => process.stderr.write(`[${path.basename(script)}] ${d}`));
  return child;
}

async function waitForHttp(url, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.status) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => { setTimeout(r, 150); });
  }
  throw new Error(`Timed out waiting for ${url}`);
}

/** Tiny cookie jar since Node's fetch doesn't persist cookies across calls. */
function makeClient(base) {
  let cookie = '';
  return async (method, urlPath, body) => {
    const res = await fetch(base + urlPath, {
      method,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    return { status: res.status, data };
  };
}

let passed = 0;
async function t(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`OK  - ${name}`);
  } catch (err) {
    console.error(`FAIL - ${name}`);
    console.error(err);
    process.exitCode = 1;
    throw err;
  }
}

async function main() {
  const mock = startProcess('mock/mock-server.js', { MOCK_PORT: String(MOCK_PORT), MOCK_JWT_TTL_MS: '3000' });
  const app = startProcess('server.js', { PORT: String(APP_PORT) });

  try {
    await waitForHttp(`${MOCK_BASE}/api/sites`);
    await waitForHttp(`${APP_BASE}/api/catalog`);

    const client = makeClient(APP_BASE);

    await t('catalog is served without auth, includes hydra-derived operations', async () => {
      const res = await client('GET', '/api/catalog');
      assert.equal(res.status, 200);
      assert.ok(res.data.entityTypes.length > 10);
      assert.ok(res.data.operations.find((o) => o.id === 'entity_create'));
      assert.ok(res.data.operations.length > 100, 'expected hydra-derived operations to be merged in');
      assert.ok(res.data.operations.find((o) => o.id === 'hydra_attributeGroup_create'));
      assert.ok(res.data.operations.find((o) => o.id === 'hydra_role_list'));
    });

    await t('login without 2FA authenticates immediately', async () => {
      const res = await client('POST', '/api/auth/login', { baseUrl: MOCK_BASE, email: 'no2fa@test.com', password: 'password123' });
      assert.equal(res.status, 200);
      assert.equal(res.data.status, 'authenticated');
    });

    await t('site list + resolve', async () => {
      const res = await client('GET', '/api/sites');
      assert.equal(res.status, 200);
      assert.equal(res.data.length, 2);
      assert.ok(res.data.some((s) => s.id === 37));
    });

    await t('entity_types_list returns the real per-site list, including types not in the curated catalog', async () => {
      const res = await client('POST', '/api/call', { operationId: 'entity_types_list', siteId: 37, query: {} });
      assert.equal(res.data.status, 200);
      const members = res.data.data['hydra:member'];
      assert.ok(members.length >= 5, 'expected curated + uncurated mock entity types');
      assert.ok(members.some((m) => m.id === 55501), 'expected an uncurated entity type to be present for the fallback UI path');
    });

    let promotionId;
    await t('create a Promotion', async () => {
      const res = await client('POST', '/api/call', {
        operationId: 'entity_create', siteId: 37,
        body: { entityType: '/api/entity_types/2304', values: { internal_name: '[TEST] Promotion', title: '[TEST] Promotion' } },
      });
      assert.equal(res.data.status, 201);
      promotionId = res.data.data.id;
    });

    let brandId;
    await t('create a Casino Brand referencing the promotion', async () => {
      const res = await client('POST', '/api/call', {
        operationId: 'entity_create', siteId: 37,
        body: { entityType: '/api/entity_types/2321', values: { internal_name: '[TEST] Brand', review_promotions: [{ promotion: promotionId }] } },
      });
      assert.equal(res.data.status, 201);
      brandId = res.data.data.id;
    });

    await t('423 exclusivity rule — reusing the promotion on a 2nd brand fails', async () => {
      const res = await client('POST', '/api/call', {
        operationId: 'entity_create', siteId: 37,
        body: { entityType: '/api/entity_types/2321', values: { internal_name: '[TEST] Brand 2', review_promotions: [{ promotion: promotionId }] } },
      });
      assert.equal(res.data.status, 423);
    });

    let reviewId;
    await t('create a Review page with an embedded Brand widget', async () => {
      const res = await client('POST', '/api/call', {
        operationId: 'entity_create', siteId: 37,
        body: {
          entityType: '/api/entity_types/12331', layout: '/api/layouts/50',
          values: {
            internal_name: '[TEST] Review', title: '[TEST] Review', slug: 'test-review-it', status: 'draft',
            widgets: [{ collectionKey: 'k1', entityTypeId: 12979, sortOrder: 0, type: 'EmbeddedInternalEntity', values: { entity_type_select: brandId }, options: { container: 'c1' } }],
          },
        },
      });
      assert.equal(res.data.status, 201);
      reviewId = res.data.data.id;
    });

    await t('publish + revalidate', async () => {
      const pub = await client('POST', '/api/call', {
        operationId: 'entity_publish', siteId: 37, pathParams: { id: reviewId }, body: { fullEntity: { id: reviewId } },
      });
      assert.equal(pub.data.status, 200);
      const reval = await client('POST', '/api/call', {
        operationId: 'revalidate', siteId: 37, body: { urls: ['test-review-it'] },
      });
      assert.equal(reval.data.status, 200);
      assert.equal(reval.data.data.success, true);
    });

    await t('status transition to archive, then delete', async () => {
      const status = await client('POST', '/api/call', {
        operationId: 'entity_status', siteId: 37, pathParams: { id: reviewId }, body: { status: 'archive' },
      });
      assert.equal(status.data.status, 200);
      const del = await client('POST', '/api/call', {
        operationId: 'entity_delete', siteId: 37, pathParams: { id: reviewId },
      });
      assert.equal(del.data.status, 204);
    });

    await t('media upload (multipart, base64 -> FormData)', async () => {
      const base64 = Buffer.from('fake-image-bytes').toString('base64');
      const res = await client('POST', '/api/call', {
        operationId: 'media_upload', siteId: 37,
        body: { folder: '/api/media_folders/948' },
        file: { base64, filename: 'logo.png', mimeType: 'image/png' },
      });
      assert.equal(res.data.status, 201);
      assert.ok(res.data.data['@id'].startsWith('/api/media/'));
    });

    await t('entities_list auto-follows hydra pagination and merges all pages', async () => {
      // Mock paginates at 2 items/page — create 5 to force a 3-page fetch.
      const created = [];
      for (let i = 0; i < 5; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        const c = await client('POST', '/api/call', {
          operationId: 'entity_create', siteId: 37,
          body: { entityType: '/api/entity_types/2306', values: { payment_name: `[TEST] PM ${i}` } },
        });
        created.push(c.data.data.id);
      }
      const res = await client('POST', '/api/call', {
        operationId: 'entities_list', siteId: 37, query: { entityType: '/api/entity_types/2306', original: true },
      });
      assert.equal(res.data.status, 200);
      assert.equal(res.data.data['hydra:member'].length, 5, 'all 5 items should be merged across pages');
      assert.ok(res.data.pagination, 'pagination metadata should be present');
      assert.equal(res.data.pagination.pagesFetched, 3);
      assert.equal(res.data.pagination.itemCount, 5);
      assert.equal(res.data.pagination.truncated, false);
      assert.equal(res.data.data['hydra:view'], undefined, 'internal hydra:view bookkeeping should not leak into the merged response');
    });

    await t('widget-usage query finds the brand widget on the review page', async () => {
      // recreate since the previous test deleted it
      const create = await client('POST', '/api/call', {
        operationId: 'entity_create', siteId: 37,
        body: {
          entityType: '/api/entity_types/12331', layout: '/api/layouts/50',
          values: { internal_name: '[TEST] Review 2', title: '[TEST] Review 2', slug: 'test-review-it-2', status: 'draft',
            widgets: [{ collectionKey: 'k2', entityTypeId: 12979, sortOrder: 0, type: 'EmbeddedInternalEntity', values: { entity_type_select: brandId }, options: { container: 'c2' } }] },
        },
      });
      const newReviewId = create.data.data.id;

      const res = await client('POST', '/api/query/widget-usage', {
        scope: { type: 'site', siteId: 37 }, widgetEntityTypeId: 12979,
      });
      assert.equal(res.status, 200);
      assert.equal(res.data.totalMatches, 1);
      assert.equal(res.data.sites[0].matches[0].entityId, newReviewId);
    });

    await t('attribute query across whole CMS scopes correctly (site 37 has data, the other does not)', async () => {
      const res = await client('POST', '/api/query/attribute', {
        scope: { type: 'all' }, entityTypeIds: [12331], propertyPath: 'values.widgets[].values.entity_type_select', matchMode: 'exists',
      });
      assert.equal(res.status, 200);
      const site37 = res.data.sites.find((s) => s.siteId === 37);
      const otherSite = res.data.sites.find((s) => s.siteId !== 37);
      assert.ok(site37.matches.length >= 1);
      assert.equal(otherSite.matches.length, 0);
    });

    await t('reactive refresh: JWT expires mid-session, next call transparently refreshes and succeeds', async () => {
      await new Promise((r) => { setTimeout(r, 3200); }); // mock JWT_TTL_MS=3000
      const res = await client('POST', '/api/call', {
        operationId: 'entities_list', siteId: 37, query: { entityType: '/api/entity_types/2321', original: true },
      });
      assert.equal(res.data.status, 200);
      const status = await client('GET', '/api/auth/status');
      assert.equal(status.data.authenticated, true);
      assert.equal(status.data.lastRefreshError, null);
    });

    const client2fa = makeClient(APP_BASE);
    await t('2FA login flow: rejects wrong code, accepts correct code', async () => {
      const login = await client2fa('POST', '/api/auth/login', { baseUrl: MOCK_BASE, email: '2fa@test.com', password: 'password123' });
      assert.equal(login.data.status, '2fa_required');
      const wrong = await client2fa('POST', '/api/auth/2fa', { authCode: '000000' });
      assert.equal(wrong.status, 401);
      const right = await client2fa('POST', '/api/auth/2fa', { authCode: '123456' });
      assert.equal(right.data.status, 'authenticated');
    });

    await t('logout clears the session', async () => {
      await client2fa('POST', '/api/auth/logout');
      const status = await client2fa('GET', '/api/auth/status');
      assert.equal(status.data.authenticated, false);
    });

    console.log(`\n${passed} tests passed`);
  } finally {
    mock.kill();
    app.kill();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

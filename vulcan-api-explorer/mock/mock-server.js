'use strict';

/**
 * A tiny stand-in for the Vulcan CMS admin API, used only to exercise the
 * explorer app's auth/refresh/CRUD/query logic end to end without real
 * credentials. Shapes follow the HAR-verified doc as closely as practical;
 * it is NOT a faithful clone of the real backend.
 */

const express = require('express');
const crypto = require('crypto');

const PORT = Number(process.env.MOCK_PORT) || 4001;
const JWT_TTL_MS = Number(process.env.MOCK_JWT_TTL_MS) || 4000; // short by default so tests can prove refresh works

const app = express();
// Accept whatever content-type the client sends (ld+json etc) but never try to
// JSON-parse a multipart upload body.
app.use(express.json({
  type: (req) => !(req.headers['content-type'] || '').includes('multipart/form-data'),
  limit: '10mb',
}));

// ---------------------------------------------------------------------------
// In-memory fixtures
// ---------------------------------------------------------------------------

const USERS = {
  'no2fa@test.com': { password: 'password123', enabled2fa: false },
  '2fa@test.com': { password: 'password123', enabled2fa: true },
};
const VALID_2FA_CODE = '123456';

const SITES = {
  37: { id: 37, name: 'test.vulcan-cms.com', token: 'tok-site-37', slugPrefix: 37 },
  323733: { id: 323733, name: 'stage-bettingtop10-th.clickto.bet', token: 'tok-site-323733', slugPrefix: 323733 },
};
for (const site of Object.values(SITES)) {
  site.url = `http://localhost:${PORT}/site-mock/${site.id}`;
}

const ENTITY_TYPE_SLUGS = {
  affiliate_link: 2279,
  casino_brand: 2321,
  promotion: 2304,
};

let nextEntityId = 1000;
let nextMediaId = 148295;
let nextNetworkId = 5000;

/** entityId -> { id, entityType (typeId), values, layout, status, published, siteId } */
const entities = new Map();
/** promotionId -> brandId that has claimed it (423 exclusivity rule) */
const promotionOwners = new Map();
let sportsbookBrandCreateAttempts = 0;

// intermediateToken -> { email }
const pendingLogins = new Map();
// jwt -> { email, expiresAt }
const jwts = new Map();
// refreshToken -> { email }
const refreshTokens = new Map();

function issueJwtPair(email) {
  const token = `jwt-${crypto.randomBytes(12).toString('hex')}`;
  const refresh_token = `refresh-${crypto.randomBytes(16).toString('hex')}`;
  jwts.set(token, { email, expiresAt: Date.now() + JWT_TTL_MS });
  refreshTokens.set(refresh_token, { email });
  return { token, refresh_token };
}

function requireAuth(req, res, next) {
  const header = req.headers['jwtauthorization'];
  const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;
  const record = token && jwts.get(token);
  if (!record || record.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'invalid_or_expired_token' });
  }
  req.vulcanUser = record.email;
  next();
}

function requireSite(req, res, next) {
  const siteToken = req.headers['x-site-id'];
  const site = Object.values(SITES).find((s) => s.token === siteToken);
  if (!site) return res.status(400).json({ error: 'unknown_or_missing_x-site-id' });
  req.vulcanSite = site;
  next();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = USERS[email];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  if (!user.enabled2fa) {
    // Not spec'd by the doc for the disabled-2FA case — mock skips straight to a JWT pair.
    const pair = issueJwtPair(email);
    return res.json({ ...pair, password_expired: false, enabled2fa: false });
  }
  const intermediateToken = `intermediate-${crypto.randomBytes(12).toString('hex')}`;
  pendingLogins.set(intermediateToken, { email });
  res.json({ firstLoginAfterReset: false, token: intermediateToken, enabled2fa: true });
});

app.post('/api/login/2fa', (req, res) => {
  const { authCode, token } = req.body || {};
  const pending = pendingLogins.get(token);
  if (!pending) return res.status(401).json({ error: 'invalid_or_expired_intermediate_token' });
  if (authCode !== VALID_2FA_CODE) return res.status(401).json({ error: 'invalid_auth_code' });
  pendingLogins.delete(token);
  const pair = issueJwtPair(pending.email);
  res.json({ ...pair, password_expired: false });
});

app.post('/api/token/refresh', (req, res) => {
  const { refresh_token } = req.body || {};
  const record = refreshTokens.get(refresh_token);
  if (!record) return res.status(401).json({ error: 'invalid_refresh_token' });
  const pair = issueJwtPair(record.email);
  res.json({ token: pair.token, refresh_token: pair.refresh_token });
});

// ---------------------------------------------------------------------------
// Global
// ---------------------------------------------------------------------------

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.vulcanUser });
});

app.get('/api/sites', requireAuth, (req, res) => {
  res.json(Object.values(SITES).map(({ id, name, url, token }) => ({ id, name, url, token })));
});

app.get('/api/sites/:id', requireAuth, (req, res) => {
  const site = SITES[req.params.id];
  if (!site) return res.status(404).json({ error: 'site_not_found' });
  const { id, name, url, token } = site;
  res.json({ id, name, url, token });
});

app.get('/api/localizations', requireAuth, (req, res) => {
  res.json([{ locale: 'en' }]);
});

// ---------------------------------------------------------------------------
// Entity types
// ---------------------------------------------------------------------------

app.get('/api/entity_types', requireAuth, requireSite, (req, res) => {
  const slug = req.query.slug;
  if (slug && ENTITY_TYPE_SLUGS[slug] != null) {
    return res.json({ 'hydra:member': [{ id: ENTITY_TYPE_SLUGS[slug], slug }] });
  }
  res.json({ 'hydra:member': Object.entries(ENTITY_TYPE_SLUGS).map(([slug, id]) => ({ id, slug })) });
});

// ---------------------------------------------------------------------------
// Generic entities
// ---------------------------------------------------------------------------

function entityTypeIdFromIri(iri) {
  const m = String(iri || '').match(/(\d+)$/);
  return m ? Number(m[1]) : null;
}

function serializeEntity(e) {
  return {
    id: e.id,
    entityType: `/api/entity_types/${e.entityType}`,
    layout: e.layout || null,
    status: e.status,
    unpublishedChanges: !e.published,
    values: e.values,
    siteId: e.siteId,
  };
}

app.get('/api/entities', requireAuth, requireSite, (req, res) => {
  const typeId = entityTypeIdFromIri(req.query.entityType);
  let list = [...entities.values()].filter((e) => e.siteId === req.vulcanSite.id);
  if (typeId) list = list.filter((e) => e.entityType === typeId);
  res.json({
    'hydra:member': list.map(serializeEntity),
    'hydra:totalItems': list.length,
  });
});

app.get('/api/entities/:id', requireAuth, requireSite, (req, res) => {
  const e = entities.get(Number(req.params.id));
  if (!e || e.siteId !== req.vulcanSite.id) return res.status(404).json({ error: 'not_found' });
  res.json(serializeEntity(e));
});

app.post('/api/entities', requireAuth, requireSite, (req, res) => {
  const { entityType, layout, values } = req.body || {};
  const typeId = entityTypeIdFromIri(entityType);

  if (typeId === 2327) {
    sportsbookBrandCreateAttempts += 1;
    if (sportsbookBrandCreateAttempts === 1) {
      return res.status(423).json({ error: 'locked', message: 'Used by other entities please remove relationship with required fields' });
    }
  }

  if ((typeId === 2321 || typeId === 2327) && Array.isArray(values?.review_promotions)) {
    for (const rp of values.review_promotions) {
      const promoId = rp.promotion;
      const owner = promotionOwners.get(promoId);
      if (owner && owner !== 'PENDING_ID') {
        return res.status(423).json({ error: 'locked', message: 'Used by other entities please remove relationship with required fields' });
      }
    }
  }

  const id = nextEntityId++;
  entities.set(id, {
    id, entityType: typeId, layout: layout || null, values, status: values?.status || 'draft',
    published: false, siteId: req.vulcanSite.id,
  });

  if ((typeId === 2321 || typeId === 2327) && Array.isArray(values?.review_promotions)) {
    for (const rp of values.review_promotions) promotionOwners.set(rp.promotion, id);
  }

  res.status(201).json(serializeEntity(entities.get(id)));
});

app.put('/api/entities/:id', requireAuth, requireSite, (req, res) => {
  const e = entities.get(Number(req.params.id));
  if (!e || e.siteId !== req.vulcanSite.id) return res.status(404).json({ error: 'not_found' });
  const { values } = req.body || {};
  if (values) e.values = { ...e.values, ...values };
  res.json(serializeEntity(e));
});

app.put('/api/entities/:id/publish', requireAuth, requireSite, (req, res) => {
  const e = entities.get(Number(req.params.id));
  if (!e || e.siteId !== req.vulcanSite.id) return res.status(404).json({ error: 'not_found' });
  e.published = true;
  res.json(serializeEntity(e));
});

app.put('/api/entity_statuses/:id', requireAuth, requireSite, (req, res) => {
  const e = entities.get(Number(req.params.id));
  if (!e || e.siteId !== req.vulcanSite.id) return res.status(404).json({ error: 'not_found' });
  const { status } = req.body || {};
  if (!['draft', 'archive'].includes(status)) return res.status(400).json({ error: 'invalid_status' });
  e.status = status;
  res.status(200).json({});
});

app.delete('/api/entities/:id', requireAuth, requireSite, (req, res) => {
  const e = entities.get(Number(req.params.id));
  if (!e || e.siteId !== req.vulcanSite.id) return res.status(404).json({ error: 'not_found' });
  entities.delete(e.id);
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// Media (multipart body is not deeply parsed — mock just acks the upload)
// ---------------------------------------------------------------------------

app.post('/api/media', requireAuth, requireSite, (req, res) => {
  const id = nextMediaId++;
  res.status(201).json({ '@id': `/api/media/${id}`, '@type': 'Media' });
});

app.get('/api/media_folders', requireAuth, requireSite, (req, res) => {
  res.json({ 'hydra:member': [{ id: 948, name: '[TEST] fixtures' }] });
});

app.get('/api/media_advanceds', requireAuth, requireSite, (req, res) => {
  res.json({ 'hydra:member': [] });
});

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

const networks = new Map();

app.get('/api/networks', requireAuth, requireSite, (req, res) => {
  res.json({ 'hydra:member': [...networks.values()] });
});
app.get('/api/networks/:id', requireAuth, requireSite, (req, res) => {
  const n = networks.get(Number(req.params.id));
  if (!n) return res.status(404).json({ error: 'not_found' });
  res.json(n);
});
app.post('/api/networks', requireAuth, requireSite, (req, res) => {
  const id = nextNetworkId++;
  const n = { '@context': {}, '@type': 'Network', '@id': `/api/networks/${id}`, id, name: req.body?.name, domain: null, defaultSite: null, sitemapIndexEnabled: false };
  networks.set(id, n);
  res.status(201).json(n);
});
app.put('/api/networks/:id', requireAuth, requireSite, (req, res) => {
  const n = networks.get(Number(req.params.id));
  if (!n) return res.status(404).json({ error: 'not_found' });
  Object.assign(n, req.body);
  res.json(n);
});
app.delete('/api/networks/:id', requireAuth, requireSite, (req, res) => {
  if (!networks.has(Number(req.params.id))) return res.status(404).json({ error: 'not_found' });
  networks.delete(Number(req.params.id));
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// Site-domain endpoints (revalidate + precondition check) — NOT the admin host
// ---------------------------------------------------------------------------

app.post('/site-mock/:siteId/api/revalidate/', (req, res) => {
  res.json({ success: true });
});
app.get('/site-mock/:siteId/:slug/', (req, res) => {
  res.status(200).send('<html>ok</html>');
});

app.listen(PORT, () => {
  console.log(`Mock Vulcan API listening on http://localhost:${PORT} (JWT TTL ${JWT_TTL_MS}ms)`);
});

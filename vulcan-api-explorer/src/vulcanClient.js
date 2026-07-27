'use strict';

const axios = require('axios');

const REQUEST_TIMEOUT_MS = 15000;

class VulcanApiError extends Error {
  constructor(message, { status, data } = {}) {
    super(message);
    this.name = 'VulcanApiError';
    this.status = status;
    this.data = data;
  }
}

/** POST {baseUrl}/api/token/refresh — per doc section 1.3. */
async function refreshJwt(session) {
  if (!session.refreshToken) {
    throw new VulcanApiError('No refresh token on session — login again.', { status: 401 });
  }
  const res = await axios({
    method: 'POST',
    url: `${session.baseUrl}/api/token/refresh`,
    data: { refresh_token: session.refreshToken },
    headers: { 'Content-Type': 'application/ld+json' },
    timeout: REQUEST_TIMEOUT_MS,
    validateStatus: () => true,
  });
  if (res.status !== 200 || !res.data || !res.data.token) {
    session.clearAuth();
    throw new VulcanApiError('Token refresh failed — session expired, please log in again.', {
      status: res.status, data: res.data,
    });
  }
  session.setJwt({ token: res.data.token, refresh_token: res.data.refresh_token });
  return session.jwt;
}

/**
 * Executes one HTTP call against the Vulcan admin API (or a site's own domain
 * for revalidate/precondition calls), with the documented 401 -> refresh ->
 * retry-once behaviour baked in for authenticated calls.
 *
 * @param {object} opts
 * @param {'GET'|'POST'|'PUT'|'DELETE'} opts.method
 * @param {string} opts.url - fully-qualified URL
 * @param {boolean} opts.auth - attach jwtauthorization header
 * @param {string} [opts.siteToken] - x-site-id header value (the site's opaque token, not numeric id)
 * @param {object} [opts.headers] - extra headers
 * @param {any} [opts.data]
 * @param {object} [opts.params] - query params
 * @param {boolean} [opts.multipart] - opts.data is a FormData-like body already built by caller
 */
async function call(session, opts) {
  const {
    method, url, auth, siteToken, headers = {}, data, params, multipart,
  } = opts;

  const buildHeaders = () => {
    const h = { ...headers };
    if (!multipart && data !== undefined && !h['Content-Type']) {
      h['Content-Type'] = 'application/ld+json';
    }
    if (auth) {
      if (!session.jwt) throw new VulcanApiError('Not authenticated.', { status: 401 });
      h.jwtauthorization = `Bearer ${session.jwt}`; // custom header name, NOT "Authorization" — doc section 0
    }
    if (siteToken) h['x-site-id'] = siteToken;
    return h;
  };

  const exec = async () => axios({
    method,
    url,
    params,
    data,
    headers: buildHeaders(),
    timeout: REQUEST_TIMEOUT_MS,
    validateStatus: () => true,
    maxContentLength: 50 * 1024 * 1024,
    maxBodyLength: 50 * 1024 * 1024,
  });

  let res = await exec();

  if (res.status === 401 && auth) {
    await refreshJwt(session); // reactive refresh, per doc section 1.3 / 9
    res = await exec();
  }

  return {
    status: res.status,
    headers: res.headers,
    data: res.data,
  };
}

/** GET /api/sites/{siteId} (global scope, no x-site-id) — resolves + caches the site's token/url. */
async function resolveSite(session, siteId, { force = false } = {}) {
  const cached = session.sites.get(String(siteId));
  if (cached && !force) return cached;

  const res = await call(session, {
    method: 'GET',
    url: `${session.baseUrl}/api/sites/${encodeURIComponent(siteId)}`,
    auth: true,
  });
  if (res.status !== 200 || !res.data) {
    throw new VulcanApiError(`Failed to resolve site ${siteId}`, { status: res.status, data: res.data });
  }
  const site = {
    id: res.data.id ?? siteId,
    name: res.data.name,
    url: res.data.url,
    token: res.data.token,
    fetchedAt: Date.now(),
  };
  session.sites.set(String(siteId), site);
  return site;
}

/** GET /api/sites — list all sites (global scope). */
async function listSites(session) {
  const res = await call(session, {
    method: 'GET',
    url: `${session.baseUrl}/api/sites`,
    auth: true,
  });
  if (res.status !== 200) {
    throw new VulcanApiError('Failed to list sites', { status: res.status, data: res.data });
  }
  const raw = res.data;
  const list = Array.isArray(raw) ? raw : (raw?.['hydra:member'] || raw?.member || []);
  for (const site of list) {
    if (site && site.id != null && site.token) {
      session.sites.set(String(site.id), {
        id: site.id, name: site.name, url: site.url, token: site.token, fetchedAt: Date.now(),
      });
    }
  }
  return list;
}

module.exports = { call, refreshJwt, resolveSite, listSites, VulcanApiError };

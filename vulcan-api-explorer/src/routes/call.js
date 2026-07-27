'use strict';

const express = require('express');
const { requireSession } = require('../middleware');
const { operationById } = require('../catalog');
const { call, resolveSite, VulcanApiError } = require('../vulcanClient');

const router = express.Router();

function fillPath(template, pathParams = {}) {
  const missing = [];
  const filled = template.replace(/\{([^}]+)\}/g, (_, key) => {
    if (pathParams[key] === undefined || pathParams[key] === '') {
      missing.push(key);
      return `{${key}}`;
    }
    return encodeURIComponent(pathParams[key]);
  });
  return { filled, missing };
}

function buildQuery(query = {}, extraQuery = []) {
  const merged = { ...query };
  for (const { key, value } of extraQuery) {
    if (!key) continue;
    if (merged[key] !== undefined) {
      merged[key] = Array.isArray(merged[key]) ? [...merged[key], value] : [merged[key], value];
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

// POST /api/call
// { operationId, siteId, pathParams, query, extraQuery: [{key,value}], body, file: {base64, filename, mimeType} }
router.post('/', requireSession, async (req, res) => {
  const session = req.vsession;
  const { operationId, siteId, pathParams, query, extraQuery, body, file } = req.body || {};

  const op = operationById(operationId);
  if (!op) return res.status(400).json({ error: 'unknown_operation', operationId });

  if (op.auth && !session.isAuthenticated()) {
    return res.status(401).json({ error: 'not_authenticated', message: 'Log in before calling authenticated operations.' });
  }

  const { filled: path, missing } = fillPath(op.path, pathParams || {});
  if (missing.length) {
    return res.status(400).json({ error: 'missing_path_params', missing });
  }

  let base;
  let siteToken;
  let site = null;
  try {
    if (op.scope === 'site' || op.scope === 'site-domain') {
      if (!siteId) return res.status(400).json({ error: 'missing_site', message: 'This operation is site-scoped — pick a site first.' });
      site = await resolveSite(session, siteId);
    }
    if (op.scope === 'site-domain') {
      base = site.url.replace(/\/+$/, '');
    } else {
      base = session.baseUrl;
    }
    if (op.scope === 'site') {
      siteToken = site.token;
    }
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    return res.status(status).json({ error: 'site_resolve_failed', message: err.message });
  }

  const url = `${base}${path}`;
  const params = buildQuery(query, extraQuery || []);

  const t0 = Date.now();
  try {
    let data = body;
    let multipart = false;
    let extraHeaders = {};

    if (op.multipart) {
      multipart = true;
      const form = new FormData();
      if (file?.base64) {
        const buf = Buffer.from(file.base64, 'base64');
        form.append('file', new Blob([buf], { type: file.mimeType || 'application/octet-stream' }), file.filename || 'upload.bin');
      }
      for (const [k, v] of Object.entries(body || {})) {
        if (k === 'file') continue;
        form.append(k, v);
      }
      data = form;
    }

    const result = await call(session, {
      method: op.method,
      url,
      auth: op.auth,
      siteToken,
      headers: extraHeaders,
      data: ['GET', 'DELETE'].includes(op.method) && !multipart ? undefined : data,
      params,
      multipart,
    });

    res.json({
      status: result.status,
      ok: result.status >= 200 && result.status < 300,
      elapsedMs: Date.now() - t0,
      requestSummary: { method: op.method, url, params, siteScoped: op.scope === 'site' },
      headers: result.headers,
      data: result.data,
    });
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'call_failed', message: err.message, elapsedMs: Date.now() - t0 });
  }
});

module.exports = router;

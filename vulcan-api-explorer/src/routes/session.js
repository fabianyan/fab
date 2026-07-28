'use strict';

const express = require('express');
const { createSession, getSession, destroySession, scheduleProactiveRefresh } = require('../sessionStore');
const { call, refreshJwt, VulcanApiError } = require('../vulcanClient');
const { requireSession } = require('../middleware');

const router = express.Router();

const COOKIE_OPTS = { httpOnly: true, sameSite: 'lax', maxAge: 2 * 60 * 60 * 1000 };

function publicStatus(session) {
  if (!session) return { authenticated: false };
  return {
    authenticated: session.isAuthenticated(),
    twoFactorPending: !!session.intermediateToken,
    baseUrl: session.baseUrl,
    email: session.email,
    expiresInSeconds: session.expiresInSeconds(),
    lastRefreshError: session.lastRefreshError,
    sitesResolved: [...session.sites.values()].map((s) => ({ id: s.id, name: s.name })),
  };
}

// POST /api/auth/login { baseUrl, email, password }
router.post('/login', async (req, res) => {
  const { baseUrl, email, password } = req.body || {};
  if (!baseUrl || !email || !password) {
    return res.status(400).json({ error: 'missing_fields', message: 'baseUrl, email and password are required.' });
  }

  let session = getSession(req.cookies?.vsid);
  if (!session || session.baseUrl !== baseUrl.replace(/\/+$/, '')) {
    if (session) destroySession(session.id);
    session = createSession(baseUrl);
  }
  session.email = email;

  try {
    const result = await call(session, {
      method: 'POST',
      url: `${session.baseUrl}/api/login`,
      auth: false,
      data: { email, password },
    });

    if (result.status !== 200) {
      return res.status(result.status || 502).json({ error: 'login_failed', vulcan: result.data });
    }

    res.cookie('vsid', session.id, COOKIE_OPTS);

    if (result.data && result.data.enabled2fa === true) {
      session.intermediateToken = result.data.token;
      return res.json({ status: '2fa_required' });
    }

    if (result.data && result.data.token && result.data.refresh_token) {
      session.setJwt(result.data);
      scheduleProactiveRefresh(session, refreshJwt);
      return res.json({ status: 'authenticated', ...publicStatus(session) });
    }

    // Ambiguous shape — surface raw response so the caller can see what came back.
    session.intermediateToken = result.data?.token || null;
    return res.json({ status: 'unknown_response', vulcan: result.data });
  } catch (err) {
    return res.status(502).json({ error: 'login_error', message: err.message });
  }
});

// POST /api/auth/2fa { authCode }
router.post('/2fa', requireSession, async (req, res) => {
  const { authCode } = req.body || {};
  const session = req.vsession;
  if (!session.intermediateToken) {
    return res.status(400).json({ error: 'no_2fa_pending', message: 'No login is awaiting a 2FA code.' });
  }
  try {
    const result = await call(session, {
      method: 'POST',
      url: `${session.baseUrl}/api/login/2fa`,
      auth: false,
      data: { authCode, token: session.intermediateToken },
    });
    if (result.status !== 200 || !result.data?.token) {
      return res.status(result.status || 502).json({ error: '2fa_failed', vulcan: result.data });
    }
    session.intermediateToken = null;
    session.setJwt(result.data);
    scheduleProactiveRefresh(session, refreshJwt);
    res.json({ status: 'authenticated', ...publicStatus(session) });
  } catch (err) {
    res.status(502).json({ error: '2fa_error', message: err.message });
  }
});

// POST /api/auth/refresh — manual trigger (normally automatic)
router.post('/refresh', requireSession, async (req, res) => {
  try {
    await refreshJwt(req.vsession);
    res.json({ status: 'authenticated', ...publicStatus(req.vsession) });
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'refresh_failed', message: err.message });
  }
});

// GET /api/auth/status
router.get('/status', (req, res) => {
  const session = getSession(req.cookies?.vsid);
  res.json(publicStatus(session));
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  const session = getSession(req.cookies?.vsid);
  if (session) destroySession(session.id);
  res.clearCookie('vsid');
  res.json({ status: 'logged_out' });
});

module.exports = router;

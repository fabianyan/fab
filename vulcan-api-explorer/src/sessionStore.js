'use strict';

const crypto = require('crypto');

const JWT_LIFETIME_MS = 300 * 1000; // 300s, per doc section 1
const PROACTIVE_REFRESH_INTERVAL_MS = 4 * 60 * 1000; // ~4 min, per doc's "alternatively proactive" strategy
const SESSION_IDLE_TIMEOUT_MS = 2 * 60 * 60 * 1000; // 2h idle -> reaped

/** @type {Map<string, Session>} */
const sessions = new Map();

function newSessionId() {
  return crypto.randomBytes(24).toString('hex');
}

class Session {
  constructor(id, baseUrl) {
    this.id = id;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.email = null;
    this.intermediateToken = null;
    this.jwt = null;
    this.refreshToken = null;
    this.jwtExpiresAt = null;
    this.lastRefreshError = null;
    /** @type {Map<string, {id:string|number, name:string, url:string, token:string, fetchedAt:number}>} */
    this.sites = new Map();
    this.savedResponses = []; // { id, name, createdAt, source, keyField, valueField, items:[{key,value,raw}] }
    this.refreshTimer = null;
    this.lastSeenAt = Date.now();
  }

  touch() {
    this.lastSeenAt = Date.now();
  }

  isAuthenticated() {
    return !!(this.jwt && this.jwtExpiresAt && this.jwtExpiresAt > Date.now());
  }

  expiresInSeconds() {
    if (!this.jwtExpiresAt) return 0;
    return Math.max(0, Math.round((this.jwtExpiresAt - Date.now()) / 1000));
  }

  setJwt({ token, refresh_token }) {
    this.jwt = token;
    if (refresh_token) this.refreshToken = refresh_token;
    this.jwtExpiresAt = Date.now() + JWT_LIFETIME_MS;
    this.lastRefreshError = null;
  }

  clearAuth() {
    this.jwt = null;
    this.jwtExpiresAt = null;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}

function createSession(baseUrl) {
  const id = newSessionId();
  const session = new Session(id, baseUrl);
  sessions.set(id, session);
  return session;
}

function getSession(id) {
  const s = id ? sessions.get(id) : undefined;
  if (s) s.touch();
  return s;
}

function destroySession(id) {
  const s = sessions.get(id);
  if (s) s.clearAuth();
  sessions.delete(id);
}

/** Keeps the connection alive "as long as the user is in the app" — proactive refresh every ~4min. */
function scheduleProactiveRefresh(session, refreshFn, intervalMs = PROACTIVE_REFRESH_INTERVAL_MS) {
  if (session.refreshTimer) clearInterval(session.refreshTimer);
  session.refreshTimer = setInterval(async () => {
    if (!session.refreshToken) return;
    try {
      await refreshFn(session);
    } catch (err) {
      session.lastRefreshError = err.message || String(err);
    }
  }, intervalMs);
  session.refreshTimer.unref?.();
}

// Reap idle sessions so the in-memory store doesn't grow unbounded.
const reaper = setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastSeenAt > SESSION_IDLE_TIMEOUT_MS) destroySession(id);
  }
}, 5 * 60 * 1000);
reaper.unref?.();

module.exports = {
  createSession,
  getSession,
  destroySession,
  scheduleProactiveRefresh,
  JWT_LIFETIME_MS,
  PROACTIVE_REFRESH_INTERVAL_MS,
};

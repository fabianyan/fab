'use strict';

const { getSession } = require('./sessionStore');

function requireSession(req, res, next) {
  const id = req.cookies?.vsid;
  const session = getSession(id);
  if (!session) return res.status(401).json({ error: 'no_session', message: 'No active session — connect to a base URL and log in first.' });
  req.vsession = session;
  next();
}

function requireAuthenticated(req, res, next) {
  if (!req.vsession?.isAuthenticated()) {
    return res.status(401).json({ error: 'not_authenticated', message: 'Session is not authenticated — log in first.' });
  }
  next();
}

module.exports = { requireSession, requireAuthenticated };

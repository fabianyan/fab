'use strict';

const express = require('express');
const { requireSession, requireAuthenticated } = require('../middleware');
const { listSites, resolveSite, VulcanApiError } = require('../vulcanClient');

const router = express.Router();

router.get('/', requireSession, requireAuthenticated, async (req, res) => {
  try {
    const list = await listSites(req.vsession);
    res.json(list.map((s) => ({ id: s.id, name: s.name, url: s.url })));
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'sites_list_failed', message: err.message });
  }
});

router.get('/:id', requireSession, requireAuthenticated, async (req, res) => {
  try {
    const site = await resolveSite(req.vsession, req.params.id);
    res.json({ id: site.id, name: site.name, url: site.url });
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'site_resolve_failed', message: err.message });
  }
});

module.exports = router;

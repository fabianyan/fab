'use strict';

const express = require('express');
const { requireSession, requireAuthenticated } = require('../middleware');
const { runAttributeQuery } = require('../queryEngine');
const { ENTITY_TYPES } = require('../catalog');
const { VulcanApiError } = require('../vulcanClient');

const router = express.Router();

const PAGE_LIKE_TYPE_IDS = ENTITY_TYPES.filter((t) => t.pageLike).map((t) => t.typeId);

// POST /api/query/attribute
// { scope: {type:'site', siteId} | {type:'all'}, entityTypeIds:[...], propertyPath, matchValue?, matchMode? }
router.post('/attribute', requireSession, requireAuthenticated, async (req, res) => {
  const { scope, entityTypeIds, propertyPath, matchValue, matchMode } = req.body || {};
  if (!scope || !scope.type) return res.status(400).json({ error: 'missing_scope' });
  if (!Array.isArray(entityTypeIds) || entityTypeIds.length === 0) {
    return res.status(400).json({ error: 'missing_entity_types', message: 'Provide at least one entityTypeId to scan (or use "search across all known types" in the UI).' });
  }
  if (!propertyPath) return res.status(400).json({ error: 'missing_property_path' });

  try {
    const result = await runAttributeQuery(req.vsession, {
      scope, entityTypeIds, propertyPath, matchValue, matchMode,
    });
    res.json(result);
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'query_failed', message: err.message });
  }
});

// POST /api/query/widget-usage
// { scope, widgetEntityTypeId, hostEntityTypeIds? }
router.post('/widget-usage', requireSession, requireAuthenticated, async (req, res) => {
  const { scope, widgetEntityTypeId, hostEntityTypeIds } = req.body || {};
  if (!scope || !scope.type) return res.status(400).json({ error: 'missing_scope' });
  if (widgetEntityTypeId === undefined) return res.status(400).json({ error: 'missing_widget_entity_type_id' });

  const entityTypeIds = Array.isArray(hostEntityTypeIds) && hostEntityTypeIds.length
    ? hostEntityTypeIds
    : PAGE_LIKE_TYPE_IDS;

  try {
    const result = await runAttributeQuery(req.vsession, {
      scope,
      entityTypeIds,
      propertyPath: 'values.widgets[].entityTypeId',
      matchValue: widgetEntityTypeId,
      matchMode: 'equals',
    });
    res.json({ ...result, widgetEntityTypeId, hostEntityTypeIds: entityTypeIds });
  } catch (err) {
    const status = err instanceof VulcanApiError ? (err.status || 502) : 502;
    res.status(status).json({ error: 'query_failed', message: err.message });
  }
});

module.exports = router;

'use strict';

const { call, listSites, resolveSite } = require('./vulcanClient');
const { extractPath } = require('./jsonPath');

const MAX_PAGES_PER_SITE_TYPE = 25;
const MAX_ENTITIES_PER_SITE_TYPE = 5000;

function entityLabel(entity) {
  const v = entity.values || {};
  return v.internal_name || v.title || v.name || String(entity.id);
}

/** Fetches every entity of a given type on a site, following hydra pagination if present. */
async function fetchAllEntities(session, site, entityTypeId) {
  const results = [];
  let page = 1;
  for (; page <= MAX_PAGES_PER_SITE_TYPE; page += 1) {
    const res = await call(session, {
      method: 'GET',
      url: `${session.baseUrl}/api/entities`,
      auth: true,
      siteToken: site.token,
      params: { entityType: `/api/entity_types/${entityTypeId}`, original: true, page },
    });
    if (res.status !== 200) {
      return { results, truncated: false, error: { status: res.status, data: res.data } };
    }
    const raw = res.data;
    const list = Array.isArray(raw) ? raw : (raw?.['hydra:member'] || raw?.member || []);
    results.push(...list);
    if (results.length >= MAX_ENTITIES_PER_SITE_TYPE) return { results, truncated: true };
    const hasNext = raw && raw['hydra:view'] && raw['hydra:view']['hydra:next'];
    if (!hasNext || list.length === 0) break;
  }
  return { results, truncated: page > MAX_PAGES_PER_SITE_TYPE };
}

function matches(value, matchMode, matchValue) {
  if (matchMode === 'exists' || matchValue === undefined || matchValue === '') return true;
  if (matchMode === 'contains') return String(value ?? '').toLowerCase().includes(String(matchValue).toLowerCase());
  // 'equals' — loose compare so numeric ids typed as strings still match
  // eslint-disable-next-line eqeqeq
  return value == matchValue;
}

/**
 * Core cross-site / cross-entity-type property search.
 * @param {object} params
 * @param {{type:'site', siteId:string|number}|{type:'all'}} params.scope
 * @param {number[]} params.entityTypeIds
 * @param {string} params.propertyPath - e.g. "values.widgets[].entityTypeId"
 * @param {*} [params.matchValue]
 * @param {'exists'|'equals'|'contains'} [params.matchMode]
 */
async function runAttributeQuery(session, { scope, entityTypeIds, propertyPath, matchValue, matchMode = 'exists' }) {
  let sites;
  if (scope.type === 'all') {
    const list = await listSites(session);
    sites = list.map((s) => ({ id: s.id, name: s.name, token: session.sites.get(String(s.id))?.token, url: s.url }));
  } else {
    const site = await resolveSite(session, scope.siteId);
    sites = [site];
  }

  const perSite = [];
  let totalEntitiesScanned = 0;
  let totalMatches = 0;
  const warnings = [];

  for (const site of sites) {
    const siteMatches = [];
    for (const entityTypeId of entityTypeIds) {
      // eslint-disable-next-line no-await-in-loop
      const { results, truncated, error } = await fetchAllEntities(session, site, entityTypeId);
      if (error) {
        warnings.push(`Site ${site.name || site.id}, type ${entityTypeId}: fetch failed (HTTP ${error.status})`);
        continue;
      }
      if (truncated) warnings.push(`Site ${site.name || site.id}, type ${entityTypeId}: result set truncated at ${MAX_ENTITIES_PER_SITE_TYPE} entities/${MAX_PAGES_PER_SITE_TYPE} pages`);
      totalEntitiesScanned += results.length;

      for (const entity of results) {
        const leaves = extractPath(entity, propertyPath);
        const hits = leaves.filter((leaf) => matches(leaf.value, matchMode, matchValue));
        if (hits.length) {
          totalMatches += hits.length;
          siteMatches.push({
            entityId: entity.id,
            entityTypeId,
            label: entityLabel(entity),
            matches: hits,
          });
        }
      }
    }
    perSite.push({ siteId: site.id, siteName: site.name, matches: siteMatches });
  }

  return {
    scope,
    propertyPath,
    matchMode,
    matchValue: matchValue ?? null,
    totalEntitiesScanned,
    totalMatches,
    warnings,
    sites: perSite,
  };
}

module.exports = { runAttributeQuery, fetchAllEntities, entityLabel };

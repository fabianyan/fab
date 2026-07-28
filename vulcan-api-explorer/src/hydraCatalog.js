'use strict';

/**
 * Builds catalog operations from the REAL Vulcan API's Hydra/JSON-LD API
 * documentation (fetched by the user from their environment's
 * /api/docs.jsonld and saved to src/data/vulcan-hydra-docs.json).
 *
 * This is authoritative for: which resources exist, their fields
 * (required/readable/writeable), and which HTTP verbs each supports. It is
 * NOT authoritative for URL paths — Hydra/JSON-LD doesn't include literal
 * REST paths, only semantic links — so paths are taken from PATH_OVERRIDES
 * (confirmed via HAR recordings or our own manual testing) where known, and
 * best-effort derived (snake_case + naive pluralization) otherwise. Anything
 * not in PATH_OVERRIDES is marked confirmed:false so the UI badges it
 * "inferred — verify" rather than presenting a guess as fact.
 *
 * Resources already covered by the hand-curated catalog.js with richer,
 * purpose-built UI (dynamic entityType-aware forms, multipart upload) are
 * skipped here to avoid confusing duplicate entries: EntityResource,
 * EntityType, EntityStatus, and the plain Media upload flow.
 */

const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(__dirname, 'data', 'vulcan-hydra-docs.json');

// Confirmed via HAR recordings / manual testing against the real API — see catalog.js.
const PATH_OVERRIDES = {
  EntityType: 'entity_types',
  EntityStatus: 'entity_statuses',
  Media: 'media',
  MediaFolder: 'media_folders',
  MediaAdvanced: 'media_advanceds',
  Network: 'networks',
  Site: 'sites',
  Localization: 'localizations',
  Layout: 'layouts',
  Lock: 'locks',
};

// Classes with a purpose-built hand-curated UI already — don't duplicate.
const SKIP_CLASSES = new Set(['EntityResource', 'EntityType', 'EntityStatus']);

const CATEGORY_MAP = {
  ActivityLog: 'Activity & Admin', ActivityLogExport: 'Activity & Admin', AdminResource: 'Activity & Admin',
  Attribute: 'Attributes', AttributeType: 'Attributes', AttributeGroup: 'Attributes',
  EntityBulk: 'Entities (extra)', EntityExport: 'Entities (extra)', EntityReplacing: 'Entities (extra)',
  EntityCount: 'Entities (extra)', BulkItem: 'Entities (extra)',
  ExternalEntitiesV2: 'Entities (extra)', ExternalEntities: 'Entities (extra)', FrontendEntity: 'Entities (extra)',
  Media: 'Media (extra)', MediaGroup: 'Media (extra)', MediaAdvanced: 'Media (extra)',
  MediaSize: 'Media (extra)', MediaFolder: 'Media (extra)',
  Layout: 'Layout & Content', Container: 'Layout & Content', Segment: 'Layout & Content',
  Favorite: 'Layout & Content', Lock: 'Layout & Content',
  Site: 'Sites & Networks (extra)', Network: 'Sites & Networks (extra)', SitemapUrl: 'Sites & Networks (extra)',
  SitemapIndex: 'Sites & Networks (extra)', SitemapGeneration: 'Sites & Networks (extra)',
  NetworkSitemapGeneration: 'Sites & Networks (extra)', SiteCopyRequest: 'Sites & Networks (extra)',
  Redirect: 'Sites & Networks (extra)',
  User: 'Users & Roles', UserActivity: 'Users & Roles', Role: 'Users & Roles',
  Permission: 'Users & Roles', ResetPassword: 'Users & Roles',
  Localization: 'Translations & Localizations', Translation: 'Translations & Localizations',
  KandyTrackingLinksSync: 'Kandy Integration', KandySingleTrackingLinksSyncResource: 'Kandy Integration',
  KandyTrackingLinksSyncBulk: 'Kandy Integration',
  Widget: 'Other (deprecated)', WidgetType: 'Other (deprecated)', Page: 'Other (deprecated)',
};

function snakeCase(str) {
  return str.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

function pluralize(str) {
  if (/[sxz]$|[cs]h$/.test(str)) return `${str}es`;
  if (/[^aeiou]y$/.test(str)) return `${str.slice(0, -1)}ies`;
  return `${str}s`;
}

function resourcePath(title) {
  if (PATH_OVERRIDES[title]) return { slug: PATH_OVERRIDES[title], confirmed: true };
  return { slug: pluralize(snakeCase(title)), confirmed: false };
}

const RANGE_TYPE_MAP = {
  'xmls:boolean': 'bool',
  'xmls:integer': 'int',
  'xmls:string': 'string',
  'xmls:decimal': 'string',
  'xmls:dateTime': 'string',
};

function fieldFromProperty(prop) {
  const range = prop.hydra_property?.range;
  const isMultiCardinality = prop.hydra_property && prop.hydra_property['owl:maxCardinality'] !== 1;
  let type = 'object';
  let note = prop['hydra:description'] || undefined;
  if (range && range.startsWith('#')) {
    type = isMultiCardinality ? 'array' : 'id-ref';
    note = [note, `references ${range.replace('#', '')}`].filter(Boolean).join(' — ');
  } else if (range && RANGE_TYPE_MAP[range]) {
    type = RANGE_TYPE_MAP[range];
    if (range === 'xmls:dateTime') note = [note, 'ISO 8601 datetime'].filter(Boolean).join(' — ');
    if (range === 'xmls:decimal') note = [note, 'decimal — enter as a string, e.g. "0.5"'].filter(Boolean).join(' — ');
  }
  return {
    key: prop.hydra_title,
    type,
    required: !!prop['hydra:required'],
    readable: prop['hydra:readable'] !== false,
    writeable: prop['hydra:writeable'] !== false,
    note,
  };
}

function dedupeProperties(supportedProperty) {
  const byName = new Map();
  for (const raw of supportedProperty || []) {
    const prop = { ...raw, hydra_title: raw['hydra:title'], hydra_property: raw['hydra:property'] };
    const existing = byName.get(prop.hydra_title);
    const field = fieldFromProperty(prop);
    if (!existing) {
      byName.set(prop.hydra_title, field);
    } else {
      existing.required = existing.required || field.required;
      existing.readable = existing.readable || field.readable;
      existing.writeable = existing.writeable || field.writeable;
      existing.note = existing.note || field.note;
    }
  }
  return [...byName.values()];
}

function loadHydraDocs() {
  const raw = fs.readFileSync(DATA_PATH, 'utf8');
  return JSON.parse(raw);
}

function buildHydraCatalog() {
  let docs;
  try {
    docs = loadHydraDocs();
  } catch {
    return { entityTypes: [], operations: [] };
  }

  const classes = docs['hydra:supportedClass'] || [];
  const collectionLinks = docs['hydra:collectionLinks'] || {};
  const operations = [];

  for (const cls of classes) {
    const title = cls['hydra:title'];
    if (!title || SKIP_CLASSES.has(title)) continue;
    if (['Entrypoint', 'ConstraintViolation', 'ConstraintViolationList'].includes(title)) continue;

    const category = CATEGORY_MAP[title] || 'Other (extra)';
    const { slug, confirmed: pathConfirmed } = resourcePath(title);
    const deprecated = !!cls['owl:deprecated'];
    const confirmed = deprecated ? 'partial' : pathConfirmed;
    const camelKey = title.charAt(0).toLowerCase() + title.slice(1);
    const collLink = collectionLinks[camelKey] || {};

    const fields = dedupeProperties(cls['hydra:supportedProperty']);
    const writeableFields = fields.filter((f) => f.writeable);

    if (collLink.get) {
      operations.push({
        id: `hydra_${camelKey}_list`, label: `List ${title}`, category, method: 'GET',
        path: `/api/${slug}`, scope: 'site', auth: true, confirmed,
        notes: deprecated ? 'Marked deprecated in the API docs — may be removed.' : undefined,
      });
    }
    if (collLink.post) {
      operations.push({
        id: `hydra_${camelKey}_create`, label: `Create ${title}`, category, method: 'POST',
        path: `/api/${slug}`, scope: 'site', auth: true, confirmed, entityAware: false,
        body: writeableFields,
        notes: deprecated ? 'Marked deprecated in the API docs — may be removed.' : undefined,
      });
    }

    const itemOps = cls['hydra:supportedOperation'] || [];
    const seenMethods = new Set();
    for (const op of itemOps) {
      const method = op['hydra:method'];
      if (!method || method === 'POST' || seenMethods.has(method)) continue;
      seenMethods.add(method);
      const verbLabel = { GET: 'Get', PUT: 'Replace', PATCH: 'Update', DELETE: 'Delete' }[method] || method;
      operations.push({
        id: `hydra_${camelKey}_${method.toLowerCase()}`, label: `${verbLabel} ${title}`, category, method,
        path: `/api/${slug}/{id}`, scope: 'site', auth: true, confirmed,
        pathParams: [{ key: 'id', type: 'string', required: true }],
        body: (method === 'PUT' || method === 'PATCH') ? writeableFields : undefined,
        notes: op['owl:deprecated'] || deprecated ? 'Marked deprecated in the API docs — may be removed.' : undefined,
      });
    }
  }

  return { operations };
}

module.exports = { buildHydraCatalog };

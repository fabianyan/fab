'use strict';

/**
 * Everything in this file is transcribed from
 * "Vulcan CMS — API Flow Documentation" (HAR-verified admin API recordings).
 * `confirmed` mirrors the doc's own confidence: true = HAR-verified,
 * 'partial' = documented but with an open question, false = inferred/not observed.
 *
 * OPERATIONS below is extended at load time with operations derived from the
 * real API's Hydra/JSON-LD documentation (src/hydraCatalog.js) — see that
 * file for how paths/fields are derived and what's still just inferred.
 */

const { buildHydraCatalog } = require('./hydraCatalog');

// ---------------------------------------------------------------------------
// Entity types (section "Entity type IDs" + the per-type sections 4/7/8/8A-8I)
// ---------------------------------------------------------------------------

const ENTITY_TYPES = [
  {
    typeId: 2321, key: 'casino_brand', label: 'Casino Brand', category: 'Brand',
    layout: null, pageLike: false, confirmed: true,
    fields: [
      { key: 'internal_name', type: 'string', required: true, note: '[TEST] prefix on test data' },
      { key: 'review_fields.brand.brand_name', type: 'string' },
      { key: 'review_fields.brand.brand_logo', type: 'id-ref', note: 'Media id' },
      { key: 'review_fields.brand.brand_logo_cta_promo', type: 'id-ref', note: 'Media id' },
      { key: 'scores', type: 'array', note: '[{score_category_select: <Score category id>, score: <int>}]' },
      { key: 'review_link_types.default_url.default_link', type: 'json-string', note: 'JSON-string-in-JSON: {"type":"affiliate_link",...,"affiliate":<id>,...}' },
      { key: 'review_link_types.default_url.default_cta_text', type: 'string' },
      { key: 'review_promotions', type: 'array', note: '[{promotion: <Promotion id>}] — one promotion per brand only (423 if reused)' },
      { key: 'editor_references', type: 'array', note: '[<Affiliate link id>]' },
      { key: 'brand_features', type: 'object', required: false, note: '{brand_features_local:[], brand_features_global:[]} each item: {features_title, features_type, features_icon, no_icon_local, active}' },
      { key: 'payment_methods', type: 'array', required: false, note: 'Payment Method ids (type 2306)' },
      { key: 'kandy_brand_id', type: 'nullable', required: false },
      { key: 'payout_speed', type: 'nullable', required: false },
      { key: 'label_select', type: 'nullable', required: false },
      { key: 'promotions_topx', type: 'nullable', required: false },
      { key: 'first_seen_live_string', type: 'nullable', required: false },
    ],
  },
  {
    typeId: 2327, key: 'sportsbook_brand', label: 'Sportsbook Brand', category: 'Brand',
    layout: null, pageLike: false, confirmed: true,
    note: '423 seen on create — retry once (transient lock).',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'review_fields', type: 'object' },
      { key: 'scores', type: 'array' },
      { key: 'review_link_types', type: 'object' },
      { key: 'review_promotions', type: 'array' },
      { key: 'brand_features', type: 'object' },
      { key: 'payment_methods', type: 'array' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2310, key: 'score_category', label: 'Score Category', category: 'Classifier', confirmed: true,
    note: 'GET-OR-CREATE — one per entity type per site, never deleted.',
    fields: [
      { key: 'score_category_name', type: 'string', required: true },
    ],
  },
  {
    typeId: 2304, key: 'promotion', label: 'Promotion', category: 'Promotion', confirmed: true,
    note: 'FRESH per brand — a promotion referenced by a second brand returns HTTP 423.',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'activated_promotion', type: 'bool' },
      { key: 'type_input_element', type: 'array', note: '[<Promotion Type id> (2303)]' },
      { key: 'sport_input_element', type: 'array', note: '[<Sport id> (2301)]' },
      { key: 'leagues_input_element', type: 'array', note: '[<League/Event id> (2302)] — multi-reference proven' },
      { key: 'promotions.bonus_cta_link', type: 'json-string', note: 'JSON-string-in-JSON: {"type":"affiliate_link",...,"affiliate":<id>,...}' },
      { key: 'promotions.bonus_cta_text', type: 'string' },
      { key: 'promotions.bonus_mark_as_default', type: 'bool' },
    ],
  },
  {
    typeId: 2303, key: 'promotion_type', label: 'Promotion Type', category: 'Classifier', confirmed: true,
    note: 'GET-OR-CREATE, one per site.',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'slug_not_visual', type: 'string' },
      { key: 'title', type: 'string' },
      { key: 'description', type: 'string' },
    ],
  },
  {
    typeId: 2301, key: 'sport', label: 'Sport', category: 'Classifier', confirmed: true,
    note: 'GET-OR-CREATE, one per site. Same shape as Promotion Type.',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'slug_not_visual', type: 'string' },
      { key: 'title', type: 'string' },
      { key: 'description', type: 'string' },
    ],
  },
  {
    typeId: 2302, key: 'league_event', label: 'League / Event', category: 'Classifier', confirmed: true,
    note: 'GET-OR-CREATE, one per site. Same shape as Promotion Type.',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'slug_not_visual', type: 'string' },
      { key: 'title', type: 'string' },
      { key: 'description', type: 'string' },
    ],
  },
  {
    typeId: 2279, key: 'affiliate_link', label: 'Affiliate Link', category: 'Affiliate', confirmed: true,
    note: 'RESOLVE-ONLY — synced from a 3rd party; never create. Resolve fresh every run.',
    fields: [
      { key: 'title', type: 'string' },
      { key: 'cloaked_url', type: 'string' },
      { key: 'destination_url', type: 'string' },
      { key: 'alternative_destination_url', type: 'string' },
      { key: 'affiliate_link_redirect_type', type: 'string' },
      { key: 'affiliate_link_target', type: 'string' },
      { key: 'affiliate_brand', type: 'id-ref' },
      { key: 'affiliate_link_nofollow', type: 'bool' },
      { key: 'is_affiliate_link_deprecated', type: 'bool' },
      { key: 'editor_references', type: 'array' },
      { key: 'kandy_campaign', type: 'nullable' },
      { key: 'kandy_campaign_id', type: 'nullable' },
      { key: 'kandy_tracking_link_id', type: 'nullable' },
      { key: 'kandy_parent_tracking_link_id', type: 'nullable' },
      { key: 'kandy_creation_date', type: 'nullable' },
      { key: 'kandy_dynamic_parameter', type: 'nullable' },
    ],
  },
  {
    typeId: 2300, key: 'game', label: 'Game', category: 'Game', confirmed: true,
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'game_fields.game_name', type: 'string' },
      { key: 'game_fields.game_screenshot', type: 'id-ref', note: 'Media id' },
      { key: 'game_fields.portrait_logo', type: 'id-ref', note: 'Media id' },
      { key: 'game_fields.game_ggs_provider', type: 'id-ref', note: 'Game provider id (2296)' },
      { key: 'game_fields.game_ggs_game_type', type: 'id-ref', note: 'Game type id (2297)' },
      { key: 'game_fields.game_operator', type: 'array', note: '[<Brand id>]' },
      { key: 'game_fields.game_score', type: 'int' },
      { key: 'game_fields.game_device_type_supported', type: 'array', note: '["mobile","tablet","desktop"]' },
      { key: 'review_link_group', type: 'object' },
    ],
  },
  {
    typeId: 2296, key: 'game_provider', label: 'Game Provider (sub-entity)', category: 'Game', confirmed: true,
    note: 'GET-OR-CREATE candidate, one per site.',
    fields: [
      { key: 'ggs_provider_internal_name', type: 'string', required: true },
      { key: 'ggs_provider_value', type: 'string' },
      { key: 'ggs_provider_logo', type: 'id-ref', note: 'Media id' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2297, key: 'game_type', label: 'Game Type (sub-entity)', category: 'Game', confirmed: true,
    note: 'GET-OR-CREATE candidate, one per site.',
    fields: [
      { key: 'ggs_game_type_internal_name', type: 'string', required: true },
      { key: 'ggs_game_type_field_value', type: 'string' },
      { key: 'ggs_game_type_logo', type: 'id-ref', note: 'Media id' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2306, key: 'payment_method', label: 'Payment Method', category: 'Payment', confirmed: true,
    fields: [
      { key: 'payment_name', type: 'string', required: true },
      { key: 'payment_type', type: 'string' },
      { key: 'payment_icon', type: 'id-ref', note: 'Media id' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 12967, key: 'global_brands_ranking', label: 'Global Brands Ranking', category: 'Brand', confirmed: true,
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'brands_type', type: 'string', note: '"sportsbook" | "casino" | "poker" — selects which list is active' },
      { key: 'sportsbook_brands', type: 'array', note: '[{sportsbook_brand:<Brand id>, global_ranking_score:<int>, global_brands_scheduled:<bool>, brand_display_period:{...}}]' },
      { key: 'casino_brands', type: 'array' },
      { key: 'poker_brands', type: 'array' },
    ],
  },
  {
    typeId: 2318, key: 'brand_feature', label: 'Brand Feature (sub-entity)', category: 'Brand', confirmed: 'partial',
    note: 'Standalone type referenced inside brand_features arrays; standalone create/edit shape not directly HAR-captured.',
    fields: [
      { key: 'features_title', type: 'string' },
      { key: 'features_type', type: 'string', note: '"positive" | ... (other values unconfirmed)' },
      { key: 'features_icon', type: 'id-ref' },
      { key: 'no_icon_local', type: 'bool' },
      { key: 'active', type: 'string', note: '"activate" | "deactivate"' },
    ],
  },
  {
    typeId: 12331, key: 'review_page', label: 'Review Page', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    note: 'Widgets are embedded in the page payload — no separate add-widget endpoint. See widgets UUID coupling rule.',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true, note: 'e.g. test-review-{RUN_ID}' },
      { key: 'status', type: 'string', note: '"draft" initially' },
      { key: 'author', type: 'id-ref', required: false },
      { key: 'parent_select', type: 'id-ref', required: false },
      { key: 'post_category', type: 'array', required: false },
      { key: 'newtag', type: 'array', required: false },
      { key: 'copied_brand_id', type: 'nullable', required: false },
      { key: 'seo', type: 'object', note: '{seo_meta_title, seo_meta_description, seo_canonical_url, seo_noindex, sd_schemas:[]}' },
      { key: 'ui_options', type: 'json-string', note: 'dynamicLayoutSections; container id must match widgets[].options.container' },
      { key: 'widgets', type: 'widgets', note: 'See "Widget UUID coupling" panel; array of embedded widget objects' },
    ],
  },
  {
    typeId: 12979, key: 'brand_widget', label: 'Brand Widget (embedded, EmbeddedInternalEntity)', category: 'Widget', confirmed: true,
    note: 'Not created standalone — embedded inside a page entity\'s `widgets[]` array.',
    fields: [
      { key: 'widget_internal_name', type: 'string' },
      { key: 'entity_type_select', type: 'id-ref', note: 'Brand id shown on the widget' },
    ],
  },
  {
    typeId: 2322, key: 'author', label: 'Author', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'nickname', type: 'string' },
      { key: 'slug', type: 'string', required: true },
      { key: 'author_bio', type: 'string' },
      { key: 'profile_picture', type: 'id-ref', note: 'Media id' },
      { key: 'status', type: 'string' },
      { key: 'seo', type: 'object' },
      { key: 'news-list-common-settings', type: 'object' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2328, key: 'interstitial_page', label: 'Interstitial Page', category: 'Page', confirmed: true,
    fields: [
      { key: 'interst_page_slug', type: 'string', required: true },
      { key: 'sport_reviews', type: 'array', note: 'Review page ids' },
      { key: 'casino_reviews', type: 'array', note: 'Review page ids' },
      { key: 'app_reviews', type: 'array', note: 'Review page ids' },
      { key: 'psychic_reviews', type: 'array', note: 'Review page ids' },
    ],
  },
  {
    typeId: 2293, key: 'page_404', label: '404 Page', category: 'Page', pageLike: true, confirmed: true,
    fields: [
      { key: 'internal_name', type: 'string' },
      { key: 'title', type: 'string' },
      { key: 'slug', type: 'string' },
      { key: 'status', type: 'string' },
      { key: 'seo', type: 'object' },
      { key: 'widgets', type: 'widgets' },
    ],
  },
  {
    typeId: 2326, key: 'article', label: 'Article', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true },
      { key: 'status', type: 'string' },
      { key: 'post_category', type: 'array', note: 'Category ids' },
      { key: 'main_category', type: 'id-ref' },
      { key: 'newtag', type: 'array', note: 'Tag ids' },
      { key: 'author', type: 'id-ref' },
      { key: 'display_author_info', type: 'object', note: '{author, author_name, author_image, last_updated_date} each "yes"/"no"' },
      { key: 'display_tags', type: 'nullable' },
      { key: 'match_date_time_group', type: 'object' },
      { key: 'news_settings', type: 'object' },
      { key: 'sidebar_configuration_group', type: 'object' },
      { key: 'seo', type: 'object' },
      { key: 'widgets', type: 'widgets' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2325, key: 'tag', label: 'Tag', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true },
      { key: 'status', type: 'string' },
      { key: 'description', type: 'nullable' },
      { key: 'tag_news', type: 'nullable' },
      { key: 'news-list-common-settings', type: 'object' },
      { key: 'news_sidebar_config', type: 'object' },
      { key: 'widgets', type: 'widgets' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2324, key: 'category', label: 'Category', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true },
      { key: 'status', type: 'string' },
      { key: 'description', type: 'nullable' },
      { key: 'category_parent', type: 'id-ref', note: 'self-referential parent Category id' },
      { key: 'is_news_category', type: 'bool' },
      { key: 'category_news', type: 'nullable' },
      { key: 'news-list-common-settings', type: 'object' },
      { key: 'news_sidebar_config', type: 'object' },
      { key: 'widgets', type: 'widgets' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 12965, key: 'landing_page', label: 'Landing Page', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/424', note: '⚠️ different layout id from other page-likes (424, not 50).',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true },
      { key: 'status', type: 'string' },
      { key: 'parent_select', type: 'id-ref' },
      { key: 'author', type: 'id-ref' },
      { key: 'widgets', type: 'widgets' },
      { key: 'editor_references', type: 'array' },
    ],
  },
  {
    typeId: 2290, key: 'home_page', label: 'Home Page', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    note: '⚠️ slug is "/" (site root) — there is normally ONE home page; edit/publish it, do not create fresh. Revalidate with {"global":true}, not a slug list.',
    fields: [
      { key: 'author', type: 'id-ref', required: false },
    ],
  },
  {
    typeId: 2277, key: 'static_page', label: 'Static Page', category: 'Page', pageLike: true, confirmed: true,
    layout: '/api/layouts/50',
    fields: [
      { key: 'internal_name', type: 'string', required: true },
      { key: 'title', type: 'string', required: true },
      { key: 'slug', type: 'string', required: true },
      { key: 'status', type: 'string' },
      { key: 'author', type: 'id-ref' },
      { key: 'parent_select', type: 'id-ref' },
      { key: 'post_category', type: 'array' },
      { key: 'newtag', type: 'array' },
      { key: 'copied_game_id', type: 'nullable', note: 'mirrors review page\'s copied_brand_id' },
      { key: 'widgets', type: 'widgets' },
      { key: 'editor_references', type: 'array' },
    ],
  },
];

const PAGE_LIKE_SHARED_FIELDS = [
  'internal_name', 'alternative_title', 'slug', 'title', 'status', 'localization',
  'updated_at', 'created_at', 'editor_notes_group', 'seo', 'hreflang-connection',
  'hreflang_tags', 'additional_settings', 'breadcrumbs', 'og_image', 'scripts',
  'personalized', 'ui_options', 'editor_references', 'widgets',
];

function entityTypeById(typeId) {
  return ENTITY_TYPES.find((t) => Number(t.typeId) === Number(typeId));
}

// ---------------------------------------------------------------------------
// Operations catalog — the fixed set of endpoints + the generic entity verbs.
// `scope`: 'none' (no auth needed), 'global' (auth, no x-site-id),
//          'site' (auth + x-site-id), 'site-domain' (hits the SITE's own url,
//          not the admin host — revalidate / precondition check).
// ---------------------------------------------------------------------------

const OPERATIONS = [
  // --- Auth --------------------------------------------------------------
  {
    id: 'login', label: 'Login', category: 'Auth', method: 'POST', path: '/api/login',
    scope: 'none', auth: false, confirmed: true,
    body: [
      { key: 'email', type: 'string', required: true },
      { key: 'password', type: 'string', required: true },
    ],
    notes: 'Returns an intermediate token — NOT the JWT. If enabled2fa is true, call login_2fa next.',
  },
  {
    id: 'login_2fa', label: 'Login — 2FA', category: 'Auth', method: 'POST', path: '/api/login/2fa',
    scope: 'none', auth: false, confirmed: true,
    body: [
      { key: 'authCode', type: 'string', required: true, note: '6-digit code' },
      { key: 'token', type: 'string', required: true, note: 'the intermediate token from /api/login' },
    ],
    notes: 'Returns { token: JWT, refresh_token, password_expired }. JWT lifetime is 300s.',
  },
  {
    id: 'token_refresh', label: 'Token Refresh', category: 'Auth', method: 'POST', path: '/api/token/refresh',
    scope: 'none', auth: false, confirmed: true,
    body: [{ key: 'refresh_token', type: 'string', required: true }],
    notes: 'The app manages this automatically (reactive on 401 + proactive every ~4min). Exposed here for manual testing only.',
  },
  // --- Global --------------------------------------------------------------
  {
    id: 'me', label: 'Current user', category: 'Global', method: 'GET', path: '/api/me',
    scope: 'global', auth: true, confirmed: true,
  },
  {
    id: 'sites_list', label: 'List sites', category: 'Global', method: 'GET', path: '/api/sites',
    scope: 'global', auth: true, confirmed: 'partial',
    notes: 'Implied by "Global endpoints: /api/me, /api/sites, /api/localizations" — list shape not directly HAR-captured, only GET /api/sites/{id}.',
  },
  {
    id: 'site_get', label: 'Get site', category: 'Global', method: 'GET', path: '/api/sites/{siteId}',
    scope: 'global', auth: true, confirmed: true,
    pathParams: [{ key: 'siteId', type: 'string', required: true }],
    notes: 'Returns {id, name, url, token}. `token` is the opaque value sent as x-site-id on every site-scoped call — resolve at runtime, never hardcode; it is environment-specific.',
  },
  {
    id: 'localizations', label: 'Localizations', category: 'Global', method: 'GET', path: '/api/localizations',
    scope: 'global', auth: true, confirmed: true,
  },
  // --- Entity types --------------------------------------------------------
  {
    id: 'entity_types_list', label: 'Resolve entity type by slug', category: 'Entities', method: 'GET', path: '/api/entity_types',
    scope: 'site', auth: true, confirmed: 'partial',
    query: [{ key: 'slug', type: 'string', required: false }],
    notes: 'Prefer slug resolution — numeric entity-type IDs are not confirmed stable across environments.',
  },
  // --- Generic entity CRUD (works for any entity type in ENTITY_TYPES) ------
  {
    id: 'entities_list', label: 'List / search entities', category: 'Entities', method: 'GET', path: '/api/entities',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    query: [
      { key: 'entityType', type: 'string', required: false, note: 'IRI, e.g. /api/entity_types/2321 — auto-filled from the selected entity type' },
      { key: 'original', type: 'bool', required: false },
    ],
    notes: 'Add any extra query filters as raw key/value pairs (advanced query editor below).',
  },
  {
    id: 'entity_get', label: 'Get entity', category: 'Entities', method: 'GET', path: '/api/entities/{id}',
    scope: 'site', auth: true, confirmed: 'partial', entityAware: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
  },
  {
    id: 'entity_create', label: 'Create entity', category: 'Entities', method: 'POST', path: '/api/entities',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    body: [
      { key: 'entityType', type: 'string', required: true, note: 'IRI /api/entity_types/{typeId}' },
      { key: 'layout', type: 'string', required: false, note: 'IRI /api/layouts/{id}, or null' },
      { key: 'template', type: 'bool', required: false },
      { key: 'values', type: 'object', required: true, note: 'shape depends on the selected entity type — see fields below' },
    ],
    notes: 'One endpoint for all entity types. `[TEST]` prefix is the convention for test data.',
  },
  {
    id: 'entity_update', label: 'Update entity', category: 'Entities', method: 'PUT', path: '/api/entities/{id}',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    body: [{ key: 'values', type: 'object', required: true }],
  },
  {
    id: 'entity_publish', label: 'Publish entity', category: 'Entities', method: 'PUT', path: '/api/entities/{id}/publish',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    body: [{ key: 'fullEntity', type: 'object', required: true, note: 'the FULL entity payload again — a minimal body is NOT confirmed to work' }],
    notes: 'Publish is NOT enough by itself — call revalidate afterwards or the rendered page stays stale/missing.',
  },
  {
    id: 'entity_status', label: 'Unpublish / Archive (status transition)', category: 'Entities', method: 'PUT', path: '/api/entity_statuses/{id}',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    pathParams: [{ key: 'id', type: 'string', required: true, note: "the entity's own id" }],
    body: [{ key: 'status', type: 'enum', options: ['draft', 'archive'], required: true }],
    notes: 'Tiny body, not the full entity. Only draft/archive confirmed — re-publish through this endpoint is unconfirmed. Revalidate after.',
  },
  {
    id: 'entity_delete', label: 'Delete entity', category: 'Entities', method: 'DELETE', path: '/api/entities/{id}',
    scope: 'site', auth: true, confirmed: true, entityAware: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    notes: 'Revalidate after, for anything that renders on a live page. Delete brands/promotions last (reverse of creation order) to avoid 423.',
  },
  // --- Media --------------------------------------------------------------
  {
    id: 'media_upload', label: 'Upload media', category: 'Media', method: 'POST', path: '/api/media',
    scope: 'site', auth: true, confirmed: true,
    multipart: true,
    body: [
      { key: 'file', type: 'file', required: true },
      { key: 'folder', type: 'string', required: true, note: 'IRI string, e.g. /api/media_folders/948 — NOT a numeric id' },
    ],
    notes: 'Response has no plain `id` — parse it from `@id` (last path segment).',
  },
  {
    id: 'media_folders_list', label: 'List media folders', category: 'Media', method: 'GET', path: '/api/media_folders',
    scope: 'site', auth: true, confirmed: true,
    query: [{ key: 'order[localizations.name]', type: 'string', required: false, default: 'asc' }],
  },
  {
    id: 'media_advanced_list', label: 'List media (advanced/self-heal lookup)', category: 'Media', method: 'GET', path: '/api/media_advanceds',
    scope: 'site', auth: true, confirmed: true,
    query: [{ key: 'folder', type: 'string', required: false }],
  },
  // --- Networks (own endpoint, not /api/entities) --------------------------
  {
    id: 'networks_list', label: 'List networks', category: 'Networks', method: 'GET', path: '/api/networks',
    scope: 'site', auth: true, confirmed: false,
    notes: 'Not directly HAR-captured — inferred for symmetry with create/update/delete. Verify before relying on it.',
  },
  {
    id: 'networks_get', label: 'Get network', category: 'Networks', method: 'GET', path: '/api/networks/{id}',
    scope: 'site', auth: true, confirmed: false,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    notes: 'Not directly HAR-captured — inferred. Verify before relying on it.',
  },
  {
    id: 'networks_create', label: 'Create network', category: 'Networks', method: 'POST', path: '/api/networks',
    scope: 'site', auth: true, confirmed: true,
    body: [{ key: 'name', type: 'string', required: true }],
  },
  {
    id: 'networks_update', label: 'Update network', category: 'Networks', method: 'PUT', path: '/api/networks/{id}',
    scope: 'site', auth: true, confirmed: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    body: [
      { key: 'name', type: 'string', required: true },
      { key: 'domain', type: 'nullable' },
      { key: 'defaultSite', type: 'nullable' },
      { key: 'sitemapIndexEnabled', type: 'bool' },
    ],
    notes: 'Edit sends the full hydra/JSON-LD object back (@context, @type, @id, id, ...).',
  },
  {
    id: 'networks_delete', label: 'Delete network', category: 'Networks', method: 'DELETE', path: '/api/networks/{id}',
    scope: 'site', auth: true, confirmed: true,
    pathParams: [{ key: 'id', type: 'string', required: true }],
    notes: 'No revalidate observed for network operations.',
  },
  // --- Revalidate / precondition (hits the SITE domain, not admin) ---------
  {
    id: 'revalidate', label: 'Revalidate site cache', category: 'Revalidate', method: 'POST', path: '/api/revalidate/',
    scope: 'site-domain', auth: false, confirmed: true,
    body: [
      { key: 'urls', type: 'array', required: false, note: 'slugs to refresh, e.g. ["category"]' },
      { key: 'global', type: 'bool', required: false, note: 'true = whole-site refresh; use for Home Page (slug "/") or after a global archive' },
    ],
    notes: 'MANDATORY after publish / status change / delete of anything that renders on a live page. Whether it requires auth is an open question in the doc — sent without jwtauthorization in recordings.',
  },
  {
    id: 'precondition_check', label: 'Precondition check (page is live)', category: 'Revalidate', method: 'GET', path: '/{slug}/',
    scope: 'site-domain', auth: false, confirmed: true,
    pathParams: [{ key: 'slug', type: 'string', required: true }],
    notes: 'Assert HTTP 200 before any test assertion runs; failure means PRECONDITION_FAILED, not a test failure.',
  },
];

const ALL_OPERATIONS = [...OPERATIONS, ...buildHydraCatalog().operations];

function operationsCatalog() {
  return {
    entityTypes: ENTITY_TYPES.map((t) => ({
      typeId: t.typeId, key: t.key, label: t.label, category: t.category,
      layout: t.layout || null, pageLike: !!t.pageLike, confirmed: t.confirmed,
      note: t.note || null, fields: t.fields,
    })),
    operations: ALL_OPERATIONS.map((op) => ({ ...op })),
    pageLikeSharedFields: PAGE_LIKE_SHARED_FIELDS,
  };
}

function operationById(id) {
  return ALL_OPERATIONS.find((op) => op.id === id);
}

module.exports = { ENTITY_TYPES, OPERATIONS, entityTypeById, operationById, operationsCatalog };

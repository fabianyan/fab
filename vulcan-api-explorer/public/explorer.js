import { api } from './api.js';
import { addSavedResponse, detectArrayRoot, getByPath } from './state.js';
import { openLinkPicker } from './linkPicker.js';
import { renderSavedList } from './saved.js';

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function widgetTemplate() {
  const sectionId = uuid();
  const containerId = uuid();
  return [
    {
      collectionKey: uuid(), name: '', isCreated: true,
      entityTypeId: 12979, sortOrder: 0, entityId: null,
      type: 'EmbeddedInternalEntity', valuesStatus: 'ready',
      values: { widget_internal_name: '[TEST] Brand widget', entity_type_select: null },
      options: { container: containerId, layout: '/api/layouts/50', desktop_width: 100, isHidden: false },
    },
  ].map((w) => w); // returns widgets array; sectionId/containerId also needed for ui_options — surfaced via note
}

function setDeep(obj, path, value) {
  const keys = path.split('.');
  let node = obj;
  for (let i = 0; i < keys.length - 1; i += 1) {
    const k = keys[i];
    if (typeof node[k] !== 'object' || node[k] === null) node[k] = {};
    node = node[k];
  }
  node[keys[keys.length - 1]] = value;
}

function badge(text, cls) {
  const span = document.createElement('span');
  span.className = `badge ${cls}`;
  span.textContent = text;
  return span;
}

function confirmedBadge(confirmed) {
  if (confirmed === true) return badge('HAR-verified', 'badge-confirmed');
  if (confirmed === 'partial') return badge('partially documented', 'badge-partial');
  return badge('inferred — verify', 'badge-unconfirmed');
}

export function initExplorer(catalog) {
  const el = {
    siteSelect: document.getElementById('siteSelect'),
    refreshSitesBtn: document.getElementById('refreshSitesBtn'),
    categorySelect: document.getElementById('categorySelect'),
    entityTypeSelect: document.getElementById('entityTypeSelect'),
    entityTypesNote: document.getElementById('entityTypesNote'),
    operationSelect: document.getElementById('operationSelect'),
    opBadges: document.getElementById('opBadges'),
    opNotes: document.getElementById('opNotes'),
    paramForm: document.getElementById('paramForm'),
    advancedQueryBlock: document.getElementById('advancedQueryBlock'),
    extraQueryRows: document.getElementById('extraQueryRows'),
    addQueryRowBtn: document.getElementById('addQueryRowBtn'),
    sendBtn: document.getElementById('sendBtn'),
    callError: document.getElementById('callError'),
    responseMeta: document.getElementById('responseMeta'),
    responseActions: document.getElementById('responseActions'),
    responseBody: document.getElementById('responseBody'),
    downloadBtn: document.getElementById('downloadBtn'),
    saveResponseBtn: document.getElementById('saveResponseBtn'),
  };

  const state = { sites: [], lastResponse: null, lastOp: null, liveEntityTypes: null };

  function fallbackEntityType(id, label) {
    return {
      typeId: id, key: `type_${id}`, label: label || `Entity type ${id}`, category: 'Entities',
      layout: null, pageLike: false, confirmed: false,
      note: 'No curated field list for this type — edit its raw JSON `values` directly.',
      fields: [{ key: 'values', type: 'object', required: false, note: 'Full values object for this entity type — shape unknown, inspect a "List entities" / "Get entity" response first.' }],
    };
  }

  function populateEntityTypeSelect(entityTypes) {
    const previous = el.entityTypeSelect.value;
    el.entityTypeSelect.innerHTML = '<option value="">— select an entity type —</option>';
    for (const t of entityTypes) {
      const opt = document.createElement('option');
      opt.value = t.typeId; opt.textContent = `${t.label} (${t.typeId})`;
      el.entityTypeSelect.appendChild(opt);
    }
    if ([...el.entityTypeSelect.options].some((o) => o.value === previous)) {
      el.entityTypeSelect.value = previous;
    }
  }

  // --- categories -----------------------------------------------------
  const categories = [...new Set(catalog.operations.map((o) => o.category))];
  for (const c of categories) {
    const opt = document.createElement('option');
    opt.value = c; opt.textContent = c;
    el.categorySelect.appendChild(opt);
  }

  populateEntityTypeSelect(catalog.entityTypes);

  async function loadSites() {
    const res = await api.sites();
    if (!res.ok) return;
    state.sites = res.data;
    el.siteSelect.innerHTML = '<option value="">— select a site —</option>';
    for (const s of res.data) {
      const opt = document.createElement('option');
      opt.value = s.id; opt.textContent = `${s.name} (${s.id})`;
      el.siteSelect.appendChild(opt);
    }
  }
  el.refreshSitesBtn.addEventListener('click', loadSites);
  document.addEventListener('vulcan:authenticated', loadSites);

  async function refreshEntityTypesForSite(siteId) {
    if (!siteId) return;
    el.entityTypesNote.textContent = 'Loading the real entity type list for this site…';
    el.entityTypesNote.classList.remove('hidden');
    const res = await api.call({ operationId: 'entity_types_list', siteId, query: {} });
    if (!res.ok || res.data?.status !== 200) {
      el.entityTypesNote.textContent = "Couldn't load this site's live entity type list — showing the curated set from the docs only.";
      return;
    }
    const raw = res.data.data;
    const live = Array.isArray(raw) ? raw : (raw?.['hydra:member'] || raw?.member || []);
    if (!live.length) {
      el.entityTypesNote.textContent = "This site's entity type list came back empty — showing the curated set from the docs only.";
      return;
    }
    const merged = live.map((entry) => {
      const id = Number(entry.id);
      const curated = catalog.entityTypes.find((t) => t.typeId === id);
      return curated || fallbackEntityType(id, entry.name || entry.slug);
    }).sort((a, b) => a.label.localeCompare(b.label));
    state.liveEntityTypes = merged;
    populateEntityTypeSelect(merged);
    const curatedCount = merged.filter((t) => catalog.entityTypes.includes(t)).length;
    el.entityTypesNote.textContent = `${merged.length} entity types loaded from this site (${curatedCount} with curated fields, ${merged.length - curatedCount} raw-JSON fallback).`;
    renderOperation();
  }

  el.siteSelect.addEventListener('change', () => {
    state.liveEntityTypes = null;
    populateEntityTypeSelect(catalog.entityTypes);
    el.entityTypesNote.classList.add('hidden');
    refreshEntityTypesForSite(el.siteSelect.value);
  });

  el.categorySelect.addEventListener('change', () => {
    const cat = el.categorySelect.value;
    el.entityTypeSelect.classList.toggle('hidden', cat !== 'Entities');
    el.operationSelect.innerHTML = '<option value="">— select an operation —</option>';
    for (const op of catalog.operations.filter((o) => o.category === cat)) {
      const opt = document.createElement('option');
      opt.value = op.id; opt.textContent = `${op.method} ${op.path} — ${op.label}`;
      el.operationSelect.appendChild(opt);
    }
    renderOperation();
  });

  el.entityTypeSelect.addEventListener('change', renderOperation);
  el.operationSelect.addEventListener('change', renderOperation);

  function currentEntityType() {
    const id = Number(el.entityTypeSelect.value);
    const pool = state.liveEntityTypes || catalog.entityTypes;
    return pool.find((t) => t.typeId === id) || null;
  }

  function currentOp() {
    return catalog.operations.find((o) => o.id === el.operationSelect.value) || null;
  }

  function renderBadgesAndNotes(op, entityType) {
    el.opBadges.innerHTML = '';
    el.opBadges.appendChild(badge(op.method, 'badge-method'));
    el.opBadges.appendChild(confirmedBadge(op.confirmed));
    el.opBadges.appendChild(badge(op.scope, 'badge-method'));
    if (entityType) el.opBadges.appendChild(confirmedBadge(entityType.confirmed));

    const notes = [op.notes, entityType?.note].filter(Boolean);
    el.opNotes.innerHTML = notes.length ? notes.map((n) => `<div>⚠️ ${n}</div>`).join('') : '';
  }

  function fieldRow({ key, type, required, note, options, prefill, linkable }) {
    const row = document.createElement('div');
    row.className = 'field-row';
    row.dataset.key = key;
    row.dataset.type = type;

    const wrap = document.createElement('div');
    wrap.className = 'field-input-wrap';
    const label = document.createElement('label');
    label.innerHTML = `${key}${required ? ' <span class="field-required">*</span>' : ''}`;
    wrap.appendChild(label);

    let input;
    if (type === 'bool') {
      input = document.createElement('input');
      input.type = 'checkbox';
      if (prefill) input.checked = true;
    } else if (type === 'enum') {
      input = document.createElement('select');
      for (const o of options || []) {
        const opt = document.createElement('option');
        opt.value = o; opt.textContent = o;
        input.appendChild(opt);
      }
    } else if (type === 'array' || type === 'object' || type === 'json-string' || type === 'widgets') {
      input = document.createElement('textarea');
      if (type === 'array') input.placeholder = '[]';
      if (type === 'object') input.placeholder = '{}';
      if (type === 'json-string') input.placeholder = '{"type":"affiliate_link", "affiliate": 123, ...}  — will be JSON-stringified into the field automatically';
      if (type === 'widgets') {
        input.placeholder = '[]';
        const tmplBtn = document.createElement('button');
        tmplBtn.type = 'button';
        tmplBtn.className = 'btn btn-sm btn-ghost';
        tmplBtn.textContent = 'Insert template';
        tmplBtn.addEventListener('click', () => {
          input.value = JSON.stringify(widgetTemplate(), null, 2);
        });
        wrap.appendChild(input);
        wrap.appendChild(tmplBtn);
        if (note) {
          const n = document.createElement('div');
          n.className = 'field-note';
          n.textContent = note;
          wrap.appendChild(n);
        }
        row.appendChild(wrap);
        return row;
      }
    } else if (type === 'file') {
      input = document.createElement('input');
      input.type = 'file';
    } else {
      input = document.createElement('input');
      input.type = type === 'int' ? 'number' : 'text';
      if (prefill !== undefined && prefill !== null) input.value = prefill;
      if (type === 'nullable') input.placeholder = 'null (leave blank)';
    }
    input.dataset.fieldKey = key;
    wrap.appendChild(input);

    if (note) {
      const n = document.createElement('div');
      n.className = 'field-note';
      n.textContent = note;
      wrap.appendChild(n);
    }
    row.appendChild(wrap);

    if (type === 'id-ref' || linkable) {
      const linkBtn = document.createElement('button');
      linkBtn.type = 'button';
      linkBtn.className = 'btn btn-sm btn-ghost link-btn';
      linkBtn.textContent = '🔗 link';
      linkBtn.addEventListener('click', () => openLinkPicker((value) => { input.value = value; }));
      row.appendChild(linkBtn);
    }

    return row;
  }

  function renderOperation() {
    const op = currentOp();
    el.paramForm.innerHTML = '';
    el.advancedQueryBlock.classList.add('hidden');
    el.extraQueryRows.innerHTML = '';
    el.callError.textContent = '';
    el.sendBtn.disabled = !op;
    if (!op) { el.opBadges.innerHTML = ''; el.opNotes.innerHTML = ''; return; }

    const entityType = op.entityAware ? currentEntityType() : null;
    renderBadgesAndNotes(op, entityType);

    for (const p of op.pathParams || []) {
      const row = fieldRow({ key: `path:${p.key}`, type: p.type, required: p.required, note: p.note, linkable: true });
      el.paramForm.appendChild(row);
    }

    if (op.id === 'entities_list') {
      el.advancedQueryBlock.classList.remove('hidden');
      const entityTypeIri = entityType ? `/api/entity_types/${entityType.typeId}` : '';
      el.paramForm.appendChild(fieldRow({ key: 'query:entityType', type: 'string', prefill: entityTypeIri, note: 'auto-filled from the Entity Type selected above — edit if needed' }));
      el.paramForm.appendChild(fieldRow({ key: 'query:original', type: 'bool', prefill: true }));
    } else if (op.id === 'entity_create' && entityType) {
      el.paramForm.appendChild(fieldRow({ key: 'body:entityType', type: 'string', prefill: `/api/entity_types/${entityType.typeId}`, note: 'auto-filled' }));
      el.paramForm.appendChild(fieldRow({ key: 'body:layout', type: 'nullable', prefill: entityType.layout || '' }));
      el.paramForm.appendChild(fieldRow({ key: 'body:template', type: 'bool' }));
      for (const f of entityType.fields) {
        el.paramForm.appendChild(fieldRow({ key: `values:${f.key}`, type: f.type, required: f.required, note: f.note, options: f.options }));
      }
    } else if (op.id === 'entity_update' && entityType) {
      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = 'Only the fields you fill in are sent — this is a partial update.';
      el.paramForm.appendChild(hint);
      for (const f of entityType.fields) {
        el.paramForm.appendChild(fieldRow({ key: `values:${f.key}`, type: f.type, required: false, note: f.note, options: f.options }));
      }
    } else if (op.id === 'entity_publish') {
      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = 'Publish requires the FULL entity payload. Use "Get entity" first, copy its response, and paste it below (a minimal body is not confirmed to work).';
      el.paramForm.appendChild(hint);
      el.paramForm.appendChild(fieldRow({ key: 'body:fullEntity', type: 'object', note: 'paste the full entity JSON here' }));
    } else {
      for (const q of op.query || []) {
        el.paramForm.appendChild(fieldRow({ key: `query:${q.key}`, type: q.type, required: q.required, note: q.note, options: q.options, prefill: q.default }));
      }
      for (const b of op.body || []) {
        el.paramForm.appendChild(fieldRow({ key: `body:${b.key}`, type: b.type, required: b.required, note: b.note, options: b.options }));
      }
    }
  }

  el.addQueryRowBtn.addEventListener('click', () => {
    const row = document.createElement('div');
    row.className = 'query-row';
    row.innerHTML = '<input placeholder="key" class="qk" /><input placeholder="value" class="qv" /><button type="button" class="btn btn-sm btn-ghost">✕</button>';
    row.querySelector('button').addEventListener('click', () => row.remove());
    el.extraQueryRows.appendChild(row);
  });

  function readFieldValue(row) {
    const type = row.dataset.type;
    const input = row.querySelector('[data-field-key]');
    if (!input) return undefined;
    if (type === 'bool') return input.checked;
    if (type === 'int') return input.value === '' ? undefined : Number(input.value);
    if (type === 'array' || type === 'object' || type === 'widgets') {
      if (!input.value.trim()) return type === 'array' ? [] : (type === 'widgets' ? [] : {});
      try { return JSON.parse(input.value); } catch { throw new Error(`Invalid JSON in field "${row.dataset.key}"`); }
    }
    if (type === 'json-string') {
      if (!input.value.trim()) return undefined;
      try { return JSON.stringify(JSON.parse(input.value)); } catch { throw new Error(`Invalid JSON in field "${row.dataset.key}"`); }
    }
    if (type === 'nullable') return input.value === '' ? null : input.value;
    if (type === 'file') return input.files[0] || null;
    if (type === 'id-ref') {
      if (input.value === '') return undefined;
      const n = Number(input.value);
      return Number.isNaN(n) ? input.value : n;
    }
    return input.value === '' ? undefined : input.value;
  }

  async function fileToBase64(file) {
    const buf = await file.arrayBuffer();
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  async function buildPayload(op) {
    const pathParams = {};
    const query = {};
    const body = {};
    let file = null;

    for (const row of el.paramForm.querySelectorAll('.field-row')) {
      const [scope, ...rest] = row.dataset.key.split(':');
      const key = rest.join(':');
      if (!key) continue;
      const value = readFieldValue(row);
      if (value === undefined) continue;
      if (scope === 'path') pathParams[key] = value;
      else if (scope === 'query') query[key] = value;
      else if (scope === 'values') setDeep(body, `values.${key}`, value);
      else if (scope === 'body') {
        if (key === 'fullEntity') Object.assign(body, { fullEntity: value });
        else if (value instanceof File) { file = { blob: value }; }
        else setDeep(body, key, value);
      }
    }

    if (op.multipart && file?.blob) {
      const base64 = await fileToBase64(file.blob);
      return {
        pathParams, query,
        body: { ...body, folder: body.folder },
        file: { base64, filename: file.blob.name, mimeType: file.blob.type },
      };
    }

    const extraQuery = [...el.extraQueryRows.querySelectorAll('.query-row')].map((r) => ({
      key: r.querySelector('.qk').value,
      value: r.querySelector('.qv').value,
    })).filter((r) => r.key);

    return { pathParams, query, body, extraQuery };
  }

  function renderResponse(res) {
    state.lastResponse = res;
    const status = res.status || res.data?.status || 0;
    const cls = status >= 200 && status < 300 ? 'status-2xx' : (status >= 500 ? 'status-5xx' : 'status-4xx');
    let metaHtml = `<span class="status-code ${cls}">${status}</span> <span>${res.elapsedMs ?? ''} ms</span>`;
    if (res.pagination) {
      const p = res.pagination;
      metaHtml += ` <span>${p.itemCount} items across ${p.pagesFetched} page${p.pagesFetched === 1 ? '' : 's'} (auto-fetched)</span>`;
      if (p.truncated) metaHtml += ` <span class="hint">⚠️ truncated at the page/item safety cap — not all results were fetched</span>`;
    }
    el.responseMeta.innerHTML = metaHtml;
    el.responseBody.textContent = JSON.stringify(res.data ?? res, null, 2);
    el.responseActions.classList.remove('hidden');
  }

  el.sendBtn.addEventListener('click', async () => {
    el.callError.textContent = '';
    const op = currentOp();
    if (!op) return;
    try {
      const { pathParams, query, body, extraQuery, file } = await buildPayload(op);
      const siteId = (op.scope === 'site' || op.scope === 'site-domain') ? (el.siteSelect.value || undefined) : undefined;
      if ((op.scope === 'site' || op.scope === 'site-domain') && !siteId) {
        el.callError.textContent = 'This operation needs a site — pick one above.';
        return;
      }
      el.sendBtn.disabled = true;
      const res = await api.call({ operationId: op.id, siteId, pathParams, query, body, extraQuery, file });
      state.lastOp = op;
      if (!res.ok && res.data?.error && !('status' in (res.data || {}))) {
        el.callError.textContent = res.data.message || res.data.error;
      } else {
        renderResponse(res.data);
      }
    } catch (err) {
      el.callError.textContent = err.message;
    } finally {
      el.sendBtn.disabled = false;
    }
  });

  el.downloadBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(state.lastResponse?.data ?? {}, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${state.lastOp?.id || 'response'}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // --- Save response dialog -------------------------------------------
  const saveDialog = document.getElementById('saveResponseDialog');
  const saveForm = document.getElementById('saveResponseForm');
  document.getElementById('cancelSaveResponse').addEventListener('click', () => saveDialog.close());
  el.saveResponseBtn.addEventListener('click', () => {
    if (!state.lastResponse) return;
    document.getElementById('saveResponseError').textContent = '';
    document.getElementById('saveRespName').value = state.lastOp ? `${state.lastOp.label}` : 'Saved response';
    document.getElementById('saveRespKeyField').value = 'id';
    document.getElementById('saveRespLabelField').value = 'values.internal_name';
    saveDialog.showModal();
  });
  saveForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('saveRespName').value.trim();
    const keyField = document.getElementById('saveRespKeyField').value.trim();
    const labelField = document.getElementById('saveRespLabelField').value.trim();
    const { items: rawItems } = detectArrayRoot(state.lastResponse.data);
    if (!rawItems.length) {
      document.getElementById('saveResponseError').textContent = 'This response has no rows to extract (empty list or unrecognized shape).';
      return;
    }
    const items = rawItems.map((row) => ({
      key: getByPath(row, keyField),
      label: (labelField && getByPath(row, labelField)) ?? getByPath(row, keyField),
      raw: row,
    })).filter((it) => it.key !== undefined);
    addSavedResponse({
      name,
      sourceLabel: state.lastOp ? `${state.lastOp.method} ${state.lastOp.path}` : 'unknown',
      keyField, labelField, items,
    });
    saveDialog.close();
    renderSavedList();
  });
}

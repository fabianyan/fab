import { api } from './api.js';
import { renderJsonTree } from './jsonTree.js';

export function initDbQuery(catalog) {
  const el = {
    modeBtns: [...document.querySelectorAll('.query-mode-btn')],
    attributeForm: document.getElementById('attributeQueryForm'),
    widgetForm: document.getElementById('widgetQueryForm'),
    scopeRadios: [...document.querySelectorAll('input[name="queryScope"]')],
    querySiteSelect: document.getElementById('querySiteSelect'),
    queryEntityTypes: document.getElementById('queryEntityTypes'),
    queryPropertyPath: document.getElementById('queryPropertyPath'),
    queryMatchMode: document.getElementById('queryMatchMode'),
    queryMatchValue: document.getElementById('queryMatchValue'),
    queryWidgetType: document.getElementById('queryWidgetType'),
    queryHostTypes: document.getElementById('queryHostTypes'),
    runQueryBtn: document.getElementById('runQueryBtn'),
    queryError: document.getElementById('queryError'),
    queryMeta: document.getElementById('queryMeta'),
    queryResultActions: document.getElementById('queryResultActions'),
    queryResults: document.getElementById('queryResults'),
    downloadQueryBtn: document.getElementById('downloadQueryBtn'),
    pickPropertyPathBtn: document.getElementById('pickPropertyPathBtn'),
    pathPickerDialog: document.getElementById('propertyPathPickerDialog'),
    pathPickerStatus: document.getElementById('propertyPathPickerStatus'),
    pathPickerTree: document.getElementById('propertyPathPickerTree'),
    pathPickerPreview: document.getElementById('propertyPathPickerPreview'),
    closePathPicker: document.getElementById('closePropertyPathPicker'),
  };

  let mode = 'attribute';
  let lastResult = null;

  for (const t of catalog.entityTypes) {
    const opt1 = document.createElement('option');
    opt1.value = t.typeId; opt1.textContent = `${t.label} (${t.typeId})`;
    el.queryEntityTypes.appendChild(opt1);
    const opt2 = document.createElement('option');
    opt2.value = t.typeId; opt2.textContent = `${t.label} (${t.typeId})`;
    el.queryHostTypes.appendChild(opt2);
  }
  for (const t of catalog.entityTypes.filter((t) => t.category === 'Widget')) {
    const opt = document.createElement('option');
    opt.value = t.typeId; opt.textContent = `${t.label} (${t.typeId})`;
    el.queryWidgetType.appendChild(opt);
  }

  async function loadSites() {
    const res = await api.sites();
    if (!res.ok) return;
    el.querySiteSelect.innerHTML = '<option value="">— select a site —</option>';
    for (const s of res.data) {
      const opt = document.createElement('option');
      opt.value = s.id; opt.textContent = `${s.name} (${s.id})`;
      el.querySiteSelect.appendChild(opt);
    }
  }
  document.addEventListener('vulcan:authenticated', loadSites);

  for (const btn of el.modeBtns) {
    btn.addEventListener('click', () => {
      mode = btn.dataset.mode;
      for (const b of el.modeBtns) b.classList.toggle('active', b === btn);
      el.attributeForm.classList.toggle('hidden', mode !== 'attribute');
      el.widgetForm.classList.toggle('hidden', mode !== 'widget');
    });
  }

  function scope() {
    const type = el.scopeRadios.find((r) => r.checked)?.value || 'site';
    if (type === 'all') return { type: 'all' };
    return { type: 'site', siteId: el.querySiteSelect.value };
  }

  function selectedValues(select) {
    return [...select.selectedOptions].map((o) => Number(o.value));
  }

  function renderResults(result) {
    lastResult = result;
    el.queryMeta.innerHTML = `
      <span>Scanned <strong>${result.totalEntitiesScanned}</strong> entities</span>
      <span>·</span>
      <span><strong>${result.totalMatches}</strong> matches</span>
      ${result.warnings?.length ? `<span class="hint">⚠️ ${result.warnings.join('; ')}</span>` : ''}
    `;
    el.queryResultActions.classList.remove('hidden');
    el.queryResults.innerHTML = '';

    for (const site of result.sites) {
      const heading = document.createElement('h4');
      heading.textContent = `${site.siteName || site.siteId} — ${site.matches.length} matching entities`;
      el.queryResults.appendChild(heading);
      if (!site.matches.length) continue;

      const table = document.createElement('table');
      table.className = 'result-table';
      table.innerHTML = '<thead><tr><th>Entity ID</th><th>Type</th><th>Label</th><th>Matched value(s)</th></tr></thead>';
      const tbody = document.createElement('tbody');
      for (const m of site.matches) {
        const tr = document.createElement('tr');
        const valuesText = m.matches.map((x) => `${JSON.stringify(x.value)} @ ${x.path}`).join('<br>');
        tr.innerHTML = `<td>${m.entityId}</td><td>${m.entityTypeId}</td><td>${m.label}</td><td>${valuesText}</td>`;
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      el.queryResults.appendChild(table);
    }
  }

  el.runQueryBtn.addEventListener('click', async () => {
    el.queryError.textContent = '';
    const sc = scope();
    if (sc.type === 'site' && !sc.siteId) {
      el.queryError.textContent = 'Pick a site, or switch scope to "Whole CMS".';
      return;
    }
    el.runQueryBtn.disabled = true;
    try {
      let res;
      if (mode === 'attribute') {
        const entityTypeIds = selectedValues(el.queryEntityTypes);
        if (!entityTypeIds.length) {
          el.queryError.textContent = 'Select at least one entity type to scan.';
          return;
        }
        if (!el.queryPropertyPath.value.trim()) {
          el.queryError.textContent = 'Enter a property path.';
          return;
        }
        res = await api.queryAttribute({
          scope: sc,
          entityTypeIds,
          propertyPath: el.queryPropertyPath.value.trim(),
          matchMode: el.queryMatchMode.value,
          matchValue: el.queryMatchValue.value || undefined,
        });
      } else {
        if (!el.queryWidgetType.value) {
          el.queryError.textContent = 'Select a widget type.';
          return;
        }
        const hostEntityTypeIds = selectedValues(el.queryHostTypes);
        res = await api.queryWidgetUsage({
          scope: sc,
          widgetEntityTypeId: Number(el.queryWidgetType.value),
          hostEntityTypeIds: hostEntityTypeIds.length ? hostEntityTypeIds : undefined,
        });
      }
      if (!res.ok) {
        el.queryError.textContent = res.data?.message || res.data?.error || `HTTP ${res.status}`;
        return;
      }
      renderResults(res.data);
    } finally {
      el.runQueryBtn.disabled = false;
    }
  });

  el.downloadQueryBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(lastResult ?? {}, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `db-query-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // --- Property path picker: click a field in a real sample entity -------
  el.closePathPicker.addEventListener('click', () => el.pathPickerDialog.close());

  const PREVIEW_PLACEHOLDER = 'Hover a field below to preview its path…';

  function showPathPickerStatus(text) {
    el.pathPickerStatus.textContent = text;
    el.pathPickerTree.innerHTML = '';
    el.pathPickerPreview.textContent = PREVIEW_PLACEHOLDER;
  }

  el.pickPropertyPathBtn.addEventListener('click', async () => {
    const entityTypeIds = selectedValues(el.queryEntityTypes);
    if (!entityTypeIds.length) {
      el.queryError.textContent = 'Select at least one entity type above first — the picker needs to know what to sample.';
      return;
    }
    const siteId = el.querySiteSelect.value || [...el.querySiteSelect.options].find((o) => o.value)?.value;
    if (!siteId) {
      el.queryError.textContent = 'No site available to sample from yet — log in and pick a site first.';
      return;
    }
    el.queryError.textContent = '';
    el.pathPickerDialog.showModal();
    showPathPickerStatus('Fetching a sample entity…');

    const typeId = entityTypeIds[0];
    const typeLabel = catalog.entityTypes.find((t) => t.typeId === typeId)?.label || `type ${typeId}`;
    const siteLabel = el.querySiteSelect.selectedOptions[0]?.textContent || `site ${siteId}`;

    const res = await api.call({
      operationId: 'entities_list', siteId,
      query: { entityType: `/api/entity_types/${typeId}`, original: true },
    });
    if (!res.ok || res.data?.status !== 200) {
      showPathPickerStatus(`Couldn't fetch a sample ${typeLabel} entity from ${siteLabel}. Close this and try a different entity type or site, or type the path manually.`);
      return;
    }
    const members = res.data.data?.['hydra:member'] || [];
    if (!members.length) {
      showPathPickerStatus(`No ${typeLabel} entities exist yet on ${siteLabel} to sample from — create one first, pick a different type, or type the path manually.`);
      return;
    }

    el.pathPickerStatus.textContent = `Sample: a real ${typeLabel} entity from ${siteLabel}. Click any field below to use it.`;
    renderJsonTree(
      el.pathPickerTree,
      members[0],
      (path) => {
        el.queryPropertyPath.value = path;
        el.pathPickerDialog.close();
      },
      (path) => {
        el.pathPickerPreview.textContent = path ? `→ ${path}` : PREVIEW_PLACEHOLDER;
      },
    );
  });
}

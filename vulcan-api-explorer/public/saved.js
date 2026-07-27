import { loadSavedResponses, deleteSavedResponse } from './state.js';

const listEl = document.getElementById('savedList');

export function renderSavedList() {
  const sets = loadSavedResponses();
  listEl.innerHTML = '';
  if (!sets.length) {
    listEl.innerHTML = '<p class="hint">Nothing saved yet.</p>';
    return;
  }
  for (const set of sets) {
    const box = document.createElement('div');
    box.className = 'saved-set';

    const header = document.createElement('div');
    header.className = 'saved-set-header';
    header.innerHTML = `<strong>${set.name}</strong><span class="meta">${set.sourceLabel} · ${set.items.length} items · ${new Date(set.createdAt).toLocaleString()}</span>`;
    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-sm btn-ghost';
    delBtn.textContent = 'Delete';
    delBtn.addEventListener('click', () => { deleteSavedResponse(set.id); renderSavedList(); });
    header.appendChild(delBtn);
    box.appendChild(header);

    const table = document.createElement('table');
    table.className = 'result-table';
    table.innerHTML = `<thead><tr><th>Label</th><th>Key (value used in params)</th></tr></thead>`;
    const tbody = document.createElement('tbody');
    for (const item of set.items) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${item.label}</td><td>${item.key}</td>`;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    const itemsWrap = document.createElement('div');
    itemsWrap.className = 'saved-items';
    itemsWrap.appendChild(table);
    box.appendChild(itemsWrap);

    listEl.appendChild(box);
  }
}

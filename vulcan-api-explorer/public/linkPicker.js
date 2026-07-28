import { loadSavedResponses } from './state.js';

const dialog = document.getElementById('linkPickerDialog');
const list = document.getElementById('linkPickerList');
document.getElementById('closeLinkPicker').addEventListener('click', () => dialog.close());

export function openLinkPicker(onPick) {
  const sets = loadSavedResponses();
  list.innerHTML = '';
  if (sets.length === 0) {
    list.innerHTML = '<p class="hint">No saved responses yet — call an operation (e.g. List sites, or List entities), then use "Save response…" to build a reusable key/value set.</p>';
  }
  for (const set of sets) {
    const group = document.createElement('div');
    const heading = document.createElement('div');
    heading.className = 'meta';
    heading.textContent = `${set.name} (${set.items.length})`;
    group.appendChild(heading);
    for (const item of set.items) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = `${item.label}  →  ${item.key}`;
      btn.addEventListener('click', () => {
        onPick(item.key);
        dialog.close();
      });
      group.appendChild(btn);
    }
    list.appendChild(group);
  }
  dialog.showModal();
}

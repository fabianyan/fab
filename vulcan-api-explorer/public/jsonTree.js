/**
 * Renders an object as a clickable, expandable tree so users can pick a
 * property path visually instead of typing dot-notation by hand.
 *
 * - Leaves (string/number/boolean/null) are clickable — clicking calls
 *   onPick(path) with the exact dot-notation path to that value.
 * - Objects/arrays expand/collapse on click of their row.
 * - Arrays show only their first item as a representative sample; the path
 *   generated for anything inside it uses "[]" (not "[0]") since the query
 *   engine treats "[]" as "check every item in this array".
 * - Arrays of primitives (e.g. ["mobile","tablet","desktop"]) get one
 *   synthetic "[]" leaf row representing "each item" directly.
 */

function describeValue(value) {
  if (value === null) return { text: 'null', cls: 'tv-null' };
  if (Array.isArray(value)) return { text: `[ ]  (${value.length} item${value.length === 1 ? '' : 's'})`, cls: 'tv-array' };
  if (typeof value === 'object') return { text: `{ }  (${Object.keys(value).length} field${Object.keys(value).length === 1 ? '' : 's'})`, cls: 'tv-object' };
  if (typeof value === 'string') {
    const truncated = value.length > 60 ? `${value.slice(0, 57)}...` : value;
    return { text: `"${truncated}"`, cls: 'tv-string' };
  }
  return { text: String(value), cls: typeof value === 'boolean' ? 'tv-bool' : 'tv-number' };
}

function isLeaf(value) {
  return value === null || typeof value !== 'object';
}

function buildNode(container, label, value, path, { onPick, onHover, depth }) {
  const row = document.createElement('div');
  row.className = 'tree-row';
  row.style.paddingLeft = `${depth * 1.1}em`;

  const leaf = isLeaf(value);
  const arrayOfPrimitives = Array.isArray(value) && value.length > 0 && isLeaf(value[0]);
  const emptyArray = Array.isArray(value) && value.length === 0;
  const desc = describeValue(value);

  const toggle = document.createElement('span');
  toggle.className = 'tree-toggle';
  toggle.textContent = (leaf || arrayOfPrimitives) ? '' : '▸';
  row.appendChild(toggle);

  const keySpan = document.createElement('span');
  keySpan.className = 'tree-key';
  keySpan.textContent = label;
  row.appendChild(keySpan);

  const sep = document.createElement('span');
  sep.className = 'tree-sep';
  sep.textContent = ': ';
  row.appendChild(sep);

  const valSpan = document.createElement('span');
  valSpan.className = `tree-value ${desc.cls}`;
  valSpan.textContent = desc.text;
  row.appendChild(valSpan);

  container.appendChild(row);

  row.addEventListener('mouseenter', () => onHover(leaf || arrayOfPrimitives ? path : null));
  row.addEventListener('mouseleave', () => onHover(null));

  if (leaf) {
    row.classList.add('tree-pickable');
    row.title = `Click to use: ${path}`;
    row.addEventListener('click', () => onPick(path));
    return;
  }

  if (arrayOfPrimitives) {
    row.classList.add('tree-pickable');
    const itemPath = `${path}[]`;
    row.title = `Click to match every item: ${itemPath}`;
    row.addEventListener('click', () => onPick(itemPath));
    return;
  }

  // Expandable object or array — build children lazily on first expand.
  const childrenEl = document.createElement('div');
  childrenEl.className = 'tree-children hidden';
  container.appendChild(childrenEl);
  let built = false;

  const expand = () => {
    const isOpen = !childrenEl.classList.contains('hidden');
    if (isOpen) {
      childrenEl.classList.add('hidden');
      toggle.textContent = '▸';
      return;
    }
    childrenEl.classList.remove('hidden');
    toggle.textContent = '▾';
    if (built) return;
    built = true;

    if (emptyArray) {
      const note = document.createElement('div');
      note.className = 'tree-empty-note';
      note.style.paddingLeft = `${(depth + 1) * 1.1}em`;
      note.textContent = '(empty array on this sample — no fields to show)';
      childrenEl.appendChild(note);
      return;
    }

    if (Array.isArray(value)) {
      const sampleNote = document.createElement('div');
      sampleNote.className = 'tree-empty-note';
      sampleNote.style.paddingLeft = `${(depth + 1) * 1.1}em`;
      sampleNote.textContent = 'showing item 1 as a sample — the path below will match every item';
      childrenEl.appendChild(sampleNote);
      const sample = value[0];
      const childPath = `${path}[]`;
      for (const [k, v] of Object.entries(sample)) {
        buildNode(childrenEl, k, v, `${childPath}.${k}`, { onPick, onHover, depth: depth + 1 });
      }
      return;
    }

    for (const [k, v] of Object.entries(value)) {
      buildNode(childrenEl, k, v, path ? `${path}.${k}` : k, { onPick, onHover, depth: depth + 1 });
    }
  };

  row.classList.add('tree-expandable');
  row.addEventListener('click', expand);
}

/** @param {HTMLElement} container @param {object} data @param {(path:string)=>void} onPick @param {(path:string|null)=>void} [onHover] */
export function renderJsonTree(container, data, onPick, onHover = () => {}) {
  container.innerHTML = '';
  if (!data || typeof data !== 'object') {
    container.textContent = 'No sample data to show.';
    return;
  }
  for (const [k, v] of Object.entries(data)) {
    buildNode(container, k, v, k, { onPick, onHover, depth: 0 });
  }
}

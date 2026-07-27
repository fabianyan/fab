const STORAGE_KEY = 'vulcan-explorer-saved-responses';

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function loadSavedResponses() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function persist(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

export function addSavedResponse(entry) {
  const list = loadSavedResponses();
  const record = { id: uuid(), createdAt: new Date().toISOString(), ...entry };
  list.unshift(record);
  persist(list);
  return record;
}

export function deleteSavedResponse(id) {
  const list = loadSavedResponses().filter((r) => r.id !== id);
  persist(list);
}

/** Dot-notation getter — no array-iteration support needed here since callers
 * already work on one array item at a time. */
export function getByPath(obj, path) {
  if (!path) return obj;
  return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

/** Best-effort: find the array of "rows" inside an arbitrary API response body. */
export function detectArrayRoot(data) {
  if (Array.isArray(data)) return { items: data, rootPath: '' };
  if (data && Array.isArray(data['hydra:member'])) return { items: data['hydra:member'], rootPath: 'hydra:member' };
  if (data && Array.isArray(data.member)) return { items: data.member, rootPath: 'member' };
  if (data && typeof data === 'object') return { items: [data], rootPath: '' };
  return { items: [], rootPath: '' };
}

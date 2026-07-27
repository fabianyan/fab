'use strict';

/**
 * Minimal path walker for pulling values out of arbitrary entity JSON.
 *
 * Supports dot notation ("values.brand_features.brand_features_local"),
 * a trailing/inline "[]" to mean "iterate this array" ("values.widgets[].entityTypeId"),
 * and numeric indices ("values.widgets[0].entityTypeId").
 *
 * Returns an array of { value, path } leaves — one entry per match, with an
 * array-expanded path (e.g. "values.widgets[2].entityTypeId") so callers can
 * report exactly where a match was found.
 */
function parsePath(path) {
  return String(path)
    .split('.')
    .filter(Boolean)
    .flatMap((segment) => {
      const parts = [];
      let rest = segment;
      const arrayMatch = rest.match(/^([^\[]*)((?:\[[^\]]*\])*)$/);
      if (!arrayMatch) return [{ key: segment }];
      const [, base, brackets] = arrayMatch;
      if (base) parts.push({ key: base });
      const bracketMatches = brackets.match(/\[[^\]]*\]/g) || [];
      for (const b of bracketMatches) {
        const inner = b.slice(1, -1);
        if (inner === '') parts.push({ iterate: true });
        else parts.push({ index: Number(inner) });
      }
      return parts;
    });
}

function walk(node, segments, currentPath, results) {
  if (segments.length === 0) {
    results.push({ value: node, path: currentPath });
    return;
  }
  if (node === null || node === undefined) return;

  const [seg, ...rest] = segments;

  if (seg.key !== undefined) {
    if (typeof node !== 'object' || Array.isArray(node)) return;
    if (!(seg.key in node)) return;
    walk(node[seg.key], rest, currentPath ? `${currentPath}.${seg.key}` : seg.key, results);
    return;
  }

  if (seg.iterate) {
    if (!Array.isArray(node)) return;
    node.forEach((item, i) => walk(item, rest, `${currentPath}[${i}]`, results));
    return;
  }

  if (seg.index !== undefined) {
    if (!Array.isArray(node)) return;
    if (node[seg.index] === undefined) return;
    walk(node[seg.index], rest, `${currentPath}[${seg.index}]`, results);
    return;
  }
}

/** @returns {{value: any, path: string}[]} */
function extractPath(obj, path) {
  const segments = parsePath(path);
  const results = [];
  walk(obj, segments, '', results);
  return results;
}

module.exports = { extractPath, parsePath };

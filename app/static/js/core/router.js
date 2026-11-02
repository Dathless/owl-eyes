import { routes } from '../registry/routes.js';
export function route() {
  const [path, query = ''] = (location.hash.slice(1) || '/').split('?');
  for (const entry of routes) {
    const match = path.match(entry.pattern);
    if (match) {
      let params;
      try {
        params = Object.fromEntries((entry.keys ?? []).map((key, index) => [key, decodeURIComponent(match[index + 1] ?? '')]));
      } catch { break; }
      return {
        ...entry,
        params,
        query: new URLSearchParams(query),
      };
    }
  }
  return {
    id: 'not-found',
    params: {},
    query: new URLSearchParams(),
    view: () => import('../views/not-found.js'),
  };
}
export const go = (path) => {
  location.hash = path;
};
export function query(patch) {
  const r = route();
  for (const [k, v] of Object.entries(patch)) {
    if (v == null) r.query.delete(k);
    else r.query.set(k, v);
  }
  const path = (location.hash.slice(1) || '/').split('?')[0];
  go(path + (r.query.size ? `?${r.query}` : ''));
}
export const scanPath = (id, tab = '', params = {}) =>
  `/scans/${encodeURIComponent(id)}${tab ? `/${tab}` : ''}${Object.keys(params).length ? `?${new URLSearchParams(params)}` : ''}`;

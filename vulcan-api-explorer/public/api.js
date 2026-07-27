const BASE = '';

async function req(method, url, body) {
  const res = await fetch(BASE + url, {
    method,
    credentials: 'include',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

export const api = {
  login: (baseUrl, email, password) => req('POST', '/api/auth/login', { baseUrl, email, password }),
  twoFa: (authCode) => req('POST', '/api/auth/2fa', { authCode }),
  status: () => req('GET', '/api/auth/status'),
  logout: () => req('POST', '/api/auth/logout'),

  sites: () => req('GET', '/api/sites'),

  catalog: () => req('GET', '/api/catalog'),

  call: (payload) => req('POST', '/api/call', payload),

  queryAttribute: (payload) => req('POST', '/api/query/attribute', payload),
  queryWidgetUsage: (payload) => req('POST', '/api/query/widget-usage', payload),
};

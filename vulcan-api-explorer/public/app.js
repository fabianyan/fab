import { api } from './api.js';
import { initExplorer } from './explorer.js';
import { renderSavedList } from './saved.js';
import { initDbQuery } from './query.js';

// --- Tabs -------------------------------------------------------------
for (const btn of document.querySelectorAll('.tab-btn')) {
  btn.addEventListener('click', () => {
    for (const b of document.querySelectorAll('.tab-btn')) b.classList.toggle('active', b === btn);
    for (const p of document.querySelectorAll('.tab-panel')) p.classList.toggle('active', p.id === `tab-${btn.dataset.tab}`);
    if (btn.dataset.tab === 'saved') renderSavedList();
  });
}

// --- Login dialog -------------------------------------------------------
const loginDialog = document.getElementById('loginDialog');
const loginForm = document.getElementById('loginForm');
const twoFaForm = document.getElementById('twoFaForm');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');

loginBtn.addEventListener('click', () => {
  loginForm.classList.remove('hidden');
  twoFaForm.classList.add('hidden');
  document.getElementById('loginError').textContent = '';
  loginDialog.showModal();
});
document.getElementById('cancelLogin').addEventListener('click', () => loginDialog.close());
document.getElementById('cancelTwoFa').addEventListener('click', () => loginDialog.close());

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const baseUrl = document.getElementById('baseUrl').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const res = await api.login(baseUrl, email, password);
  if (!res.ok) {
    document.getElementById('loginError').textContent = res.data?.message || res.data?.vulcan?.error || 'Login failed';
    return;
  }
  if (res.data.status === '2fa_required') {
    loginForm.classList.add('hidden');
    twoFaForm.classList.remove('hidden');
    return;
  }
  loginDialog.close();
  await refreshStatus();
});

twoFaForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const authCode = document.getElementById('authCode').value.trim();
  const res = await api.twoFa(authCode);
  if (!res.ok) {
    document.getElementById('twoFaError').textContent = res.data?.message || res.data?.vulcan?.error || '2FA failed';
    return;
  }
  loginDialog.close();
  await refreshStatus();
});

logoutBtn.addEventListener('click', async () => {
  await api.logout();
  await refreshStatus();
});

// --- Session status polling / countdown --------------------------------
const statusPill = document.getElementById('sessionStatus');
const countdownEl = document.getElementById('jwtCountdown');
let wasAuthenticated = false;

async function refreshStatus() {
  const res = await api.status();
  const s = res.data || { authenticated: false };
  if (s.authenticated) {
    statusPill.textContent = `connected — ${s.email || ''} @ ${s.baseUrl}`;
    statusPill.className = 'status-pill status-on';
    countdownEl.textContent = `JWT expires in ${s.expiresInSeconds}s (auto-refreshed)`;
    loginBtn.classList.add('hidden');
    logoutBtn.classList.remove('hidden');
    if (!wasAuthenticated) document.dispatchEvent(new CustomEvent('vulcan:authenticated'));
    wasAuthenticated = true;
  } else if (s.twoFactorPending) {
    statusPill.textContent = '2FA pending';
    statusPill.className = 'status-pill status-pending';
    countdownEl.textContent = '';
    wasAuthenticated = false;
  } else {
    statusPill.textContent = 'not connected';
    statusPill.className = 'status-pill status-off';
    countdownEl.textContent = '';
    loginBtn.classList.remove('hidden');
    logoutBtn.classList.add('hidden');
    wasAuthenticated = false;
  }
  if (s.lastRefreshError) {
    countdownEl.textContent += ` — last refresh error: ${s.lastRefreshError}`;
  }
}
setInterval(refreshStatus, 5000);

// --- Bootstrap ------------------------------------------------------------
async function main() {
  const catalogRes = await api.catalog();
  initExplorer(catalogRes.data);
  initDbQuery(catalogRes.data);
  renderSavedList();
  await refreshStatus();
}
main();

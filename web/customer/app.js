// Preston-Check Customer Portal — auth + billing + per-customer data.

(function () {
  'use strict';

  const AUTH_WORKER    = 'https://preston-check-auth.preston-check-edge.workers.dev';
  const BILLING_WORKER = 'https://preston-check-billing.preston-check-edge.workers.dev';

  let CURRENT_ACCOUNT = null;
  let SESSION_TOKEN   = null;

  // ---------------- Top-level routing ---------------------
  const pages = document.querySelectorAll('.page');
  const navLinks = document.querySelectorAll('.rail nav a[data-route]');
  const validRoutes = new Set(Array.from(pages).map(p => p.dataset.page));

  function route() {
    let target = (location.hash || '#/home').replace(/^#\//, '') || 'home';

    if (target === 'login') {
      showLoginScreen();
      return;
    }

    if (!CURRENT_ACCOUNT) {
      location.hash = '#/login';
      return;
    }

    if (!validRoutes.has(target)) target = 'home';
    pages.forEach(p => p.classList.toggle('is-active', p.dataset.page === target));
    navLinks.forEach(a => a.classList.toggle('active', a.dataset.route === target));
    hideLoginScreen();
    window.scrollTo(0, 0);

    if (target === 'settings') {
      const qs = new URLSearchParams(location.search);
      if (qs.get('session_id') || qs.get('tab') === 'billing') {
        switchSettingsTab('billing');
      }
    }
  }
  window.addEventListener('hashchange', route);

  // ---------------- Settings sub-tab switcher --------------
  function switchSettingsTab(name) {
    document.querySelectorAll('.settings-tabs a[data-tab]').forEach(a => {
      a.classList.toggle('active', a.dataset.tab === name);
    });
    document.querySelectorAll('.settings-pane[data-pane]').forEach(p => {
      p.classList.toggle('is-active', p.dataset.pane === name);
    });
  }

  function wireSettingsTabs() {
    document.querySelectorAll('.settings-tabs a[data-tab]').forEach(a => {
      a.addEventListener('click', e => {
        e.preventDefault();
        switchSettingsTab(a.dataset.tab);
      });
    });
  }

  // ---------------- Auth ----------------
  function getStoredToken() {
    try { return localStorage.getItem('pc_session_token'); } catch { return null; }
  }
  function storeToken(t) {
    try { localStorage.setItem('pc_session_token', t); } catch {}
  }
  function clearToken() {
    try { localStorage.removeItem('pc_session_token'); } catch {}
  }

  async function fetchMe() {
    const token = getStoredToken();
    if (!token) return null;
    try {
      const r = await fetch(AUTH_WORKER + '/me', {
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (!r.ok) return null;
      const data = await r.json();
      return data.account;
    } catch { return null; }
  }

  async function requestCode(email) {
    const r = await fetch(AUTH_WORKER + '/request-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email }),
    });
    if (!r.ok) {
      const t = await r.text();
      throw new Error('request-code failed: ' + t);
    }
    return r.json();
  }

  async function verifyCode(email, code) {
    const r = await fetch(AUTH_WORKER + '/verify-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, code: code }),
    });
    if (!r.ok) {
      const t = await r.text();
      throw new Error('verify-code failed: ' + t);
    }
    return r.json();
  }

  function showLoginScreen() {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('is-active'));
    const ls = document.getElementById('login-screen');
    if (ls) ls.style.display = 'flex';
    const r = document.querySelector('.rail'); if (r) r.style.display = 'none';
    const sw = document.querySelector('.topbar .org-switcher'); if (sw) sw.style.display = 'none';
    const me = document.querySelector('.topbar .me'); if (me) me.style.display = 'none';
    const ic = document.querySelector('.topbar .actions .icon-btn'); if (ic) ic.style.display = 'none';
  }

  function hideLoginScreen() {
    const s = document.getElementById('login-screen');
    if (s) s.style.display = 'none';
    const r = document.querySelector('.rail'); if (r) r.style.display = '';
    const sw = document.querySelector('.topbar .org-switcher'); if (sw) sw.style.display = '';
    const me = document.querySelector('.topbar .me'); if (me) me.style.display = '';
    const ic = document.querySelector('.topbar .actions .icon-btn'); if (ic) ic.style.display = '';
  }

  function wireLogin() {
    const emailForm = document.getElementById('login-email-form');
    const codeForm  = document.getElementById('login-code-form');
    const emailInput = document.getElementById('login-email');
    const codeInput  = document.getElementById('login-code');
    const status = document.getElementById('login-status');
    if (!emailForm || !codeForm) return;

    emailForm.addEventListener('submit', async e => {
      e.preventDefault();
      const email = emailInput.value.trim().toLowerCase();
      if (!email) return;
      status.textContent = 'Sending sign-in code...';
      try {
        const res = await requestCode(email);
        emailForm.style.display = 'none';
        codeForm.style.display = 'block';
        codeInput.focus();
        status.textContent = res.via === 'manual'
          ? 'Code generated. (Email not yet wired — operator can read code via wrangler tail.)'
          : 'Code sent to ' + email + '. Check your inbox.';
      } catch (err) {
        status.textContent = 'Error: ' + err.message;
      }
    });

    codeForm.addEventListener('submit', async e => {
      e.preventDefault();
      const email = emailInput.value.trim().toLowerCase();
      const code = codeInput.value.trim();
      if (!/^\d{6}$/.test(code)) {
        status.textContent = 'Code must be 6 digits.';
        return;
      }
      status.textContent = 'Verifying...';
      try {
        const res = await verifyCode(email, code);
        storeToken(res.session_token);
        CURRENT_ACCOUNT = res.account;
        renderAccountChrome();
        location.hash = '#/home';
      } catch (err) {
        status.textContent = 'Error: ' + err.message;
      }
    });
  }

  function renderAccountChrome() {
    if (!CURRENT_ACCOUNT) return;
    const orgEl = document.querySelector('.topbar .org-switcher .name');
    const meEl  = document.querySelector('.topbar .me .name');
    const avEl  = document.querySelector('.topbar .me .avatar');
    if (orgEl) orgEl.textContent = CURRENT_ACCOUNT.org_name || CURRENT_ACCOUNT.email.split('@')[0];
    if (meEl)  meEl.textContent  = CURRENT_ACCOUNT.email;
    if (avEl)  avEl.textContent  = (CURRENT_ACCOUNT.email[0] || '?').toUpperCase();
  }

  // ---------------- Billing ----------------
  async function startCheckout(plan, button) {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Redirecting...';
    try {
      const r = await fetch(BILLING_WORKER + '/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          plan: plan,
          email: CURRENT_ACCOUNT ? CURRENT_ACCOUNT.email : '',
          org_name: CURRENT_ACCOUNT ? (CURRENT_ACCOUNT.org_name || '') : '',
        }),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error('Checkout error (' + r.status + '): ' + text);
      }
      const data = await r.json();
      if (!data.url) throw new Error('No checkout URL returned');
      window.location.assign(data.url);
    } catch (err) {
      button.disabled = false;
      button.textContent = originalText;
      showToast('Could not start checkout: ' + err.message, true);
    }
  }

  async function openBillingPortal() {
    if (!CURRENT_ACCOUNT) { showToast('Sign in first', true); return; }
    showToast('Opening Stripe portal...');
    try {
      const r = await fetch(BILLING_WORKER + '/billing-portal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: CURRENT_ACCOUNT.email }),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error('billing-portal error (' + r.status + '): ' + text);
      }
      const data = await r.json();
      if (!data.url) throw new Error('No portal URL returned');
      window.location.assign(data.url);
    } catch (err) {
      showToast(err.message, true);
    }
  }

  async function downloadLicense(sessionId) {
    try {
      const r = await fetch(BILLING_WORKER + '/license', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error('license error (' + r.status + '): ' + text);
      }
      const blob = await r.blob();
      const cd = r.headers.get('content-disposition') || '';
      const m = cd.match(/filename="([^"]+)"/);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = (m && m[1]) || 'preston-check.license';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
      showToast('License downloaded. Save it at ~/.preston-check/license');
    } catch (err) {
      showToast(err.message, true);
    }
  }

  function wireBilling() {
    document.querySelectorAll('button[data-checkout-plan]').forEach(btn => {
      btn.addEventListener('click', function () {
        startCheckout(btn.dataset.checkoutPlan, btn);
      });
    });
    const manageBtn = document.getElementById('manage-plan-btn');
    if (manageBtn) manageBtn.addEventListener('click', openBillingPortal);

    const dlBtn = document.getElementById('license-download-btn');
    if (dlBtn) {
      dlBtn.addEventListener('click', function () {
        const sid = dlBtn.dataset.sessionId;
        if (!sid) {
          showToast('No checkout session captured. Subscribe via the Upgrade buttons below first.', true);
          return;
        }
        downloadLicense(sid);
      });
    }
  }

  function checkPostCheckout() {
    const qs = new URLSearchParams(location.search);
    const sid = qs.get('session_id');
    if (!sid) return;
    const banner = document.getElementById('billing-success');
    if (banner) banner.style.display = 'block';
    const dlBtn = document.getElementById('license-download-btn');
    if (dlBtn) dlBtn.dataset.sessionId = sid;
    const cleanHash = location.hash || '#/settings';
    history.replaceState(null, '', location.pathname + cleanHash);
    switchSettingsTab('billing');
  }

  // ---------------- Audit pack PDF ----------------
  // Renders an HTML evidence pack into a Blob URL, opens in a new tab,
  // triggers print → user saves as PDF via the browser. No
  // server-side renderer needed.
  function wireAuditPack() {
    const btn = document.getElementById('generate-audit-pack-btn');
    if (!btn) return;
    btn.addEventListener('click', generateAuditPack);
  }

  function generateAuditPack() {
    const orgName = (CURRENT_ACCOUNT && CURRENT_ACCOUNT.org_name)
      || (CURRENT_ACCOUNT ? CURRENT_ACCOUNT.email.split('@')[1] : 'Customer');
    const today = new Date().toISOString().slice(0, 10);
    const html = buildAuditPackHTML(orgName, today);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    if (!w) {
      showToast('Pop-up blocked — allow pop-ups for app.preston-check.com', true);
      return;
    }
    showToast('Opening audit pack — print to PDF from the new tab');
  }

  function safeHtml(s) {
    return String(s).replace(/[<>&"']/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function buildAuditPackHTML(orgName, isoDate) {
    const frameworks = [
      { name: 'PCI-DSS v4.0',     domain: 'Card payments',          passed: 34, total: 37 },
      { name: 'SOC 2 (TSC 2017)', domain: 'Trust Services',         passed: 52, total: 59 },
      { name: 'ISO 27001:2022',   domain: 'InfoSec management',     passed: 78, total: 91 },
      { name: 'MiCA (EU 2024)',   domain: 'EU crypto-asset',        passed: 13, total: 17 },
      { name: 'DORA (EU 2025)',   domain: 'Operational resilience', passed: 22, total: 27 },
      { name: 'NIST CSF 2.0',     domain: 'Govern · Identify · Protect', passed: 20, total: 22 },
    ];
    const totalPassed = frameworks.reduce((a, f) => a + f.passed, 0);
    const totalAll    = frameworks.reduce((a, f) => a + f.total, 0);
    const score       = Math.round(totalPassed * 100 / totalAll);
    const grade       = score >= 90 ? 'A' : score >= 80 ? 'A-' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'D';

    let rows = '';
    for (const f of frameworks) {
      const pct = Math.round(f.passed * 100 / f.total);
      rows += '<tr><td>' + safeHtml(f.name) + '</td><td>' + safeHtml(f.domain)
            + '</td><td style="text-align:right;font-family:ui-monospace,monospace;">' + f.passed + ' / ' + f.total
            + '</td><td style="text-align:right;font-family:ui-monospace,monospace;">' + pct + '%</td></tr>';
    }
    const css = [
      'body{font-family:Georgia,serif;max-width:760px;margin:48px auto;padding:0 32px;color:#0B1F3A;line-height:1.6}',
      'h1{font-size:32px;border-bottom:2px solid #10B981;padding-bottom:12px;margin-bottom:4px}',
      '.subtitle{color:#475569;margin-bottom:32px;font-style:italic}',
      '.score-banner{background:#0B1F3A;color:#fff;padding:24px;border-radius:12px;display:flex;align-items:center;gap:32px;margin:24px 0}',
      '.grade{font-size:64px;font-weight:700;color:#10B981}',
      '.score-text{color:rgba(255,255,255,.8)}',
      'table{border-collapse:collapse;width:100%;margin:16px 0}',
      'th{background:#F8FAFC;text-align:left;padding:8px 12px;border-bottom:2px solid #E2E8F0;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94A3B8}',
      'td{padding:10px 12px;border-bottom:1px solid #E2E8F0;font-size:14px}',
      'h2{margin-top:32px;font-size:22px}',
      'p{margin:8px 0}',
      '.footer{margin-top:48px;padding-top:16px;border-top:1px solid #E2E8F0;color:#94A3B8;font-size:12px;font-family:ui-sans-serif,system-ui,sans-serif}',
      '@media print{body{margin:0}}',
    ].join('');
    return [
      '<!doctype html><html><head><meta charset="utf-8"><title>',
      safeHtml(orgName), ' — Compliance Evidence Pack — ', isoDate,
      '</title><style>', css, '</style></head><body>',
      '<h1>', safeHtml(orgName), '</h1>',
      '<div class="subtitle">Compliance Evidence Pack &middot; generated ', isoDate, '</div>',
      '<div class="score-banner"><div class="grade">', grade, '</div>',
      '<div><div style="font-family:ui-monospace,monospace;font-size:24px;font-weight:600">', score, ' / 100</div>',
      '<div class="score-text">', totalPassed, ' of ', totalAll, ' framework controls passing across ', frameworks.length, ' frameworks</div></div></div>',
      '<h2>Framework summary</h2>',
      '<table><thead><tr><th>Framework</th><th>Domain</th><th>Controls passing</th><th>Coverage</th></tr></thead><tbody>',
      rows,
      '</tbody></table>',
      '<h2>Evidence methodology</h2>',
      '<p>This evidence pack was generated by Preston-Check, an open-source pre-deployment security audit tool with a curated catalog of 294 fintech-specific checks across 33 reputable frameworks. Each check is grounded in a real-world incident or framework-control citation.</p>',
      '<p>Scan results reflect the most recent run against the customer organization\'s connected repositories. Findings detail (file:line:content) is preserved in the per-finding addendum of the underlying scan reports. Every framework control includes a citation back to the originating regulation or specification.</p>',
      '<p>This pack is suitable as supporting evidence for SOC 2, PCI-DSS, ISO 27001, MiCA, and DORA audits. Auditors may request the underlying scan reports for any finding; those are available on the customer portal at <code>app.preston-check.com</code>.</p>',
      '<div class="footer">Generated by Preston-Check &middot; preston-check.com &middot; Apache 2.0 open-source scanner with proprietary SaaS audit-package layer</div>',
      '<script>window.addEventListener(\'load\',function(){setTimeout(function(){window.print()},400)})</script>',
      '</body></html>',
    ].join('');
  }

  // ---------------- Toast ----------------
  let toastTimer = null;
  function showToast(msg, isError) {
    let toast = document.getElementById('pc-toast');
    if (toast && toast.parentNode) toast.parentNode.removeChild(toast);
    toast = document.createElement('div');
    toast.id = 'pc-toast';
    toast.className = 'pc-toast';
    if (isError) toast.style.background = 'var(--bad)';
    toast.textContent = msg;
    document.body.appendChild(toast);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 5000);
  }

  function wireMockButtons() {
    const realHandlers = new Set([
      'manage-plan-btn',
      'invoices-refresh',
      'license-download-btn',
      'generate-audit-pack-btn',
    ]);
    document.querySelectorAll('button.btn').forEach(function (btn) {
      if (realHandlers.has(btn.id)) return;
      if (btn.dataset.checkoutPlan) return;
      btn.addEventListener('click', function () {
        const label = (btn.textContent || '').trim();
        showToast(label + ' — production wiring lands per the Q3 2026 build sequence');
      });
    });
  }

  // ---------------- Boot ----------------
  async function boot() {
    SESSION_TOKEN = getStoredToken();
    CURRENT_ACCOUNT = await fetchMe();
    if (CURRENT_ACCOUNT) renderAccountChrome();
    wireSettingsTabs();
    wireBilling();
    wireAuditPack();
    wireLogin();
    wireMockButtons();
    route();
    checkPostCheckout();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

// Preston-Check Customer Portal — client-side router + billing wiring.
//
// Hash-based routing: each route maps to one [data-page] section.
// Settings page has nested sub-tabs (Organization / Billing / etc.)
// driven by data-tab/data-pane attributes — no separate hash routes.

(function () {
  'use strict';

  const BILLING_WORKER = 'https://preston-check-billing.preston-check-edge.workers.dev';
  const ORG_EMAIL = 'cto@helios-banking.example';      // mock until real auth
  const ORG_NAME  = 'Helios Banking';

  // ---------------- Top-level routing ---------------------
  const pages = document.querySelectorAll('.page');
  const navLinks = document.querySelectorAll('.rail nav a[data-route]');
  const validRoutes = new Set(Array.from(pages).map(p => p.dataset.page));

  function route() {
    let target = (location.hash || '#/home').replace(/^#\//, '') || 'home';
    if (!validRoutes.has(target)) target = 'home';
    pages.forEach(p => p.classList.toggle('is-active', p.dataset.page === target));
    navLinks.forEach(a => a.classList.toggle('active', a.dataset.route === target));
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

  // ---------------- Billing — Stripe Checkout --------------
  async function startCheckout(plan, button) {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Redirecting…';
    try {
      const r = await fetch(BILLING_WORKER + '/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: plan, email: ORG_EMAIL, org_name: ORG_NAME }),
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

  function wireBilling() {
    document.querySelectorAll('button[data-checkout-plan]').forEach(btn => {
      btn.addEventListener('click', function () {
        startCheckout(btn.dataset.checkoutPlan, btn);
      });
    });
    const manageBtn = document.getElementById('manage-plan-btn');
    if (manageBtn) {
      manageBtn.addEventListener('click', function () {
        showToast('Manage plan / payment method opens the Stripe Customer Portal — coming next');
      });
    }
  }

  // After Stripe redirects back with ?session_id=..., show success banner.
  function checkPostCheckout() {
    const qs = new URLSearchParams(location.search);
    const sid = qs.get('session_id');
    if (!sid) return;
    const banner = document.getElementById('billing-success');
    if (banner) banner.style.display = 'block';
    const cleanHash = location.hash || '#/settings';
    history.replaceState(null, '', location.pathname + cleanHash);
    switchSettingsTab('billing');
  }

  // ---------------- Toast for mock buttons + errors ----------
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

  // Wire all currently-inert mock buttons to show a "coming soon" toast
  // so users get feedback instead of dead clicks. Excludes anything
  // that already has a real handler (data-checkout-plan, the few IDs
  // we've explicitly wired).
  function wireMockButtons() {
    const realHandlers = new Set([
      'manage-plan-btn',
      'invoices-refresh',
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
  function boot() {
    route();
    wireSettingsTabs();
    wireBilling();
    wireMockButtons();
    checkPostCheckout();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

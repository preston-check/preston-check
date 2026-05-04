// Preston-Check Admin — client-side router + table renderer.
//
// Hash-based routing: each route maps to one [data-page] section in
// the DOM. One page is always active; default is "customers".
// Mock customer data is rendered into the table via DOM APIs only;
// no innerHTML on user-shaped data, so XSS surface is zero.

(function () {
  'use strict';

  // ---------------- Routing ---------------------------------------------
  const pages = document.querySelectorAll('.page');
  const links = document.querySelectorAll('.rail nav a[data-route]');
  const validRoutes = new Set(Array.from(pages).map(p => p.dataset.page));

  function route() {
    let target = (location.hash || '#/customers').replace(/^#\//, '') || 'customers';
    if (!validRoutes.has(target)) target = 'customers';
    pages.forEach(p => p.classList.toggle('is-active', p.dataset.page === target));
    links.forEach(a => a.classList.toggle('active', a.dataset.route === target));
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);
  document.addEventListener('DOMContentLoaded', route);

  // ---------------- Customer table --------------------------------------
  // Mock data. The production version reads /api/customers, gated by
  // Cloudflare Access on the admin subdomain.
  const customers = [
    { org: 'Helios Banking',     domain: 'helios-banking.com',   plan: 'ENT',   pillCls: 'pill-ent',   seats: 24, mrr: '$2,499', last: '4m ago',   risk: 'low'    },
    { org: 'Cardinal Pay',       domain: 'cardinalpay.io',       plan: 'PRO',   pillCls: 'pill-pro',   seats:  8, mrr: '$417',   last: '2h ago',   risk: 'low'    },
    { org: 'Beacon Markets',     domain: 'beacon-markets.eu',    plan: 'ENT',   pillCls: 'pill-ent',   seats: 18, mrr: '$3,250', last: '1h ago',   risk: 'low'    },
    { org: 'Sentry Treasuries',  domain: 'sentrytreasury.com',   plan: 'ENT',   pillCls: 'pill-ent',   seats: 12, mrr: '$2,416', last: '8h ago',   risk: 'low'    },
    { org: 'Yatahay Custodians', domain: 'yatahay.io',           plan: 'PRO',   pillCls: 'pill-pro',   seats:  6, mrr: '$417',   last: '1d ago',   risk: 'low'    },
    { org: 'Triple-A Custody',   domain: 'triple-a-custody.com', plan: 'PRO',   pillCls: 'pill-pro',   seats:  5, mrr: '$417',   last: '3h ago',   risk: 'low'    },
    { org: 'PerennialFi',        domain: 'perennialfi.com',      plan: 'PRO',   pillCls: 'pill-pro',   seats:  3, mrr: '$417',   last: '2d ago',   risk: 'medium' },
    { org: 'Citrine Bank',       domain: 'citrinebank.example',  plan: 'TRIAL', pillCls: 'pill-trial', seats:  2, mrr: '—',      last: 'just now', risk: 'low'    },
    { org: 'Levante Pay',        domain: 'levantepay.example',   plan: 'TRIAL', pillCls: 'pill-trial', seats:  2, mrr: '—',      last: '30m ago',  risk: 'low'    },
    { org: 'Aperture Capital',   domain: 'aperture-cap.example', plan: 'PRO',   pillCls: 'pill-pro',   seats:  9, mrr: '$417',   last: '5d ago',   risk: 'medium' },
    { org: 'NorthSpire FinTech', domain: 'northspire.example',   plan: 'PRO',   pillCls: 'pill-pro',   seats:  4, mrr: '$83',    last: '12d ago',  risk: 'high'   },
    { org: 'Kestrel Brokers',    domain: 'kestrelbrokers.io',    plan: 'PRO',   pillCls: 'pill-pro',   seats:  7, mrr: '$417',   last: '15d ago',  risk: 'high'   },
  ];
  const riskPillClass = { low: 'pill-good', medium: 'pill-warn', high: 'pill-bad' };
  const riskLabel = { low: 'Low', medium: 'Medium', high: 'High' };

  function el(tag, opts) {
    const node = document.createElement(tag);
    if (!opts) return node;
    if (opts.cls) node.className = opts.cls;
    if (opts.text != null) node.textContent = opts.text;
    return node;
  }

  function renderCustomers() {
    const tbody = document.getElementById('customer-rows');
    if (!tbody) return;
    customers.forEach(c => {
      const tr = el('tr');

      const tdOrg = el('td', { cls: 'org', text: c.org });
      const sub = el('span', { cls: 'sub', text: c.domain });
      tdOrg.appendChild(sub);
      tr.appendChild(tdOrg);

      const tdPlan = el('td');
      tdPlan.appendChild(el('span', { cls: 'pill ' + c.pillCls, text: c.plan }));
      tr.appendChild(tdPlan);

      tr.appendChild(el('td', { text: String(c.seats) }));
      tr.appendChild(el('td', { cls: 'num', text: c.mrr }));
      tr.appendChild(el('td', { text: c.last }));

      const tdRisk = el('td');
      tdRisk.appendChild(el('span', { cls: 'pill ' + riskPillClass[c.risk], text: riskLabel[c.risk] }));
      tr.appendChild(tdRisk);

      const tdActions = el('td', { cls: 'actions-cell' });
      tdActions.appendChild(el('button', { cls: 'btn btn-ghost', text: 'View' }));
      tr.appendChild(tdActions);

      tbody.appendChild(tr);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderCustomers);
  } else {
    renderCustomers();
  }
})();

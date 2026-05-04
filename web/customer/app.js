// Preston-Check Customer Portal — client-side router.
//
// Hash-based routing: each route maps to one [data-page] section in
// the DOM. One page is always active; default is "home".

(function () {
  'use strict';

  const pages = document.querySelectorAll('.page');
  const links = document.querySelectorAll('.rail nav a[data-route]');
  const validRoutes = new Set(Array.from(pages).map(p => p.dataset.page));

  function route() {
    let target = (location.hash || '#/home').replace(/^#\//, '') || 'home';
    if (!validRoutes.has(target)) target = 'home';
    pages.forEach(p => p.classList.toggle('is-active', p.dataset.page === target));
    links.forEach(a => a.classList.toggle('active', a.dataset.route === target));
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);
  document.addEventListener('DOMContentLoaded', route);
})();

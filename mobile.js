/* GH-CYBERCOMPLY — shared mobile behaviour (drawer + responsive tables).
   Pure progressive enhancement: pages still render without it. */
(function () {
  'use strict';

  var DESKTOP_MIN = 1024; // must match the nav breakpoint in mobile.css
  var lastFocus = null;

  function $(id) { return document.getElementById(id); }
  function isOpen() { var d = $('drawer'); return !!d && d.classList.contains('open'); }

  function setOpen(open) {
    var drawer = $('drawer'), overlay = $('overlay'), btn = $('menuBtn');
    if (!drawer || !overlay) return;
    if (open === isOpen()) return;

    drawer.classList.toggle('open', open);
    overlay.classList.toggle('open', open);
    drawer.setAttribute('aria-hidden', open ? 'false' : 'true');
    document.body.classList.toggle('nav-open', open);
    if (btn) {
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    }

    if (open) {
      lastFocus = document.activeElement;
      var first = drawer.querySelector('.drawer-close') || drawer.querySelector('a, button');
      if (first) setTimeout(function () { first.focus(); }, 50);
    } else {
      // Return focus to whatever opened the drawer (falls back to the menu button)
      var target = lastFocus && lastFocus !== document.body ? lastFocus : btn;
      if (target && target.focus) target.focus();
      lastFocus = null;
    }
  }

  // Global: pages call this from inline onclick handlers.
  window.toggleDrawer = function () { setOpen(!isOpen()); };

  document.addEventListener('keydown', function (e) {
    if (!isOpen()) return;
    if (e.key === 'Escape') { setOpen(false); return; }
    if (e.key !== 'Tab') return;
    // Keep keyboard focus inside the open drawer
    var f = $('drawer').querySelectorAll('a[href], button:not([disabled])');
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });

  window.addEventListener('resize', function () {
    if (window.innerWidth >= DESKTOP_MIN && isOpen()) setOpen(false);
  });

  /* Responsive tables: copy each <th> label onto its cells (data-label) so the
     CSS card layout can show them. Re-runs when rows are re-rendered by page JS. */
  function enhanceTable(table) {
    var heads = Array.prototype.map.call(table.querySelectorAll('thead th'), function (th) {
      return th.textContent.trim();
    });
    Array.prototype.forEach.call(table.querySelectorAll('tbody tr'), function (tr) {
      Array.prototype.forEach.call(tr.children, function (td, i) {
        if (td.colSpan > 1) return;
        if (heads[i] && td.getAttribute('data-label') !== heads[i]) td.setAttribute('data-label', heads[i]);
      });
    });
  }

  function init() {
    var drawer = $('drawer');
    if (drawer) {
      drawer.setAttribute('aria-hidden', 'true');
      // Close the drawer when a link is chosen (same-page links don't reload)
      drawer.addEventListener('click', function (e) {
        if (e.target.closest && e.target.closest('a')) setOpen(false);
      });
    }

    Array.prototype.forEach.call(document.querySelectorAll('table.responsive-table'), function (table) {
      // Table semantics are dropped by some browsers once CSS sets display:block; restore them.
      table.setAttribute('role', 'table');
      Array.prototype.forEach.call(table.querySelectorAll('thead, tbody'), function (g) { g.setAttribute('role', 'rowgroup'); });
      enhanceTable(table);
      var tbody = table.querySelector('tbody');
      if (tbody && 'MutationObserver' in window) {
        new MutationObserver(function () {
          Array.prototype.forEach.call(tbody.querySelectorAll('tr'), function (tr) { tr.setAttribute('role', 'row'); });
          Array.prototype.forEach.call(tbody.querySelectorAll('td'), function (td) { td.setAttribute('role', 'cell'); });
          enhanceTable(table);
        }).observe(tbody, { childList: true });
      }
      Array.prototype.forEach.call(table.querySelectorAll('tr'), function (tr) { tr.setAttribute('role', 'row'); });
      Array.prototype.forEach.call(table.querySelectorAll('th'), function (th) { th.setAttribute('role', 'columnheader'); });
      Array.prototype.forEach.call(table.querySelectorAll('td'), function (td) { td.setAttribute('role', 'cell'); });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

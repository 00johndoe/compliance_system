/* GH-CYBERCOMPLY — accessible custom dropdown (progressive enhancement of <select>).
   - The real <select> remains in the DOM (visually hidden) and stays the source of truth:
     .value reads/writes, `change`/`input` events and the `field-error` class keep working.
   - ARIA "select-only combobox": button[role=combobox] + ul[role=listbox], focus stays on
     the button and aria-activedescendant points at the active option.
   - The panel is positioned with position:fixed from the trigger's rectangle, kept inside the
     viewport and flipped above the trigger when there is no room below. */
(function () {
  'use strict';

  var COUNT = /^(.*?)\s*\((\d+)\)\s*$/;            // "Governance & Leadership (10)"
  var VALUE = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  var CHEVRON = '<svg class="gs-chev" viewBox="0 0 20 20" width="16" height="16" aria-hidden="true" focusable="false"><path d="M5.5 7.5 10 12l4.5-4.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  var CHECK = '<svg class="gs-check" viewBox="0 0 20 20" aria-hidden="true" focusable="false"><path d="M4.5 10.5l3.6 3.6L15.5 6.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  var uid = 0;
  var current = null; // the instance whose panel is open
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  function accessibleName(select) {
    var aria = select.getAttribute('aria-label');
    if (aria) return aria;
    var lab = select.labels && select.labels[0];
    if (lab) {
      var c = lab.cloneNode(true);
      Array.prototype.forEach.call(c.querySelectorAll('select, .gs, .gs-trigger'), function (n) { n.remove(); });
      if (c.textContent.trim()) return c.textContent.replace(/\*/g, '').trim();
    }
    var prev = select.previousElementSibling;                       // <label>Sector *</label><select>
    if (prev && prev.tagName === 'LABEL') return prev.textContent.replace(/\*/g, '').trim();
    return select.name || 'Choose an option';
  }

  function enhance(select) {
    if (!select || select._gs || select.multiple || select.size > 1 || select.hasAttribute('data-native')) return;

    var id = 'gs' + (++uid), listId = id + '-list';
    var name = accessibleName(select);

    var wrap = document.createElement('div');
    wrap.className = 'gs';
    select.parentNode.insertBefore(wrap, select);
    wrap.appendChild(select);
    select.classList.add('gs-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    var trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.id = id;
    trigger.className = 'gs-trigger';
    trigger.setAttribute('role', 'combobox');
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.setAttribute('aria-controls', listId);
    trigger.setAttribute('aria-label', name);
    if (select.required) trigger.setAttribute('aria-required', 'true');
    trigger.innerHTML = '<span class="gs-value"></span>' + CHEVRON;
    wrap.appendChild(trigger);
    var valueEl = trigger.firstChild;

    var panel = null, active = -1, typed = '', typedTimer = null;

    function labelOf(opt) { var m = COUNT.exec(opt.text); return m ? { label: m[1], count: m[2] } : { label: opt.text, count: '' }; }

    // ── keep the visible trigger in step with the real select ──
    function sync() {
      var opt = select.options[select.selectedIndex];
      var parts = opt ? labelOf(opt) : { label: '', count: '' };
      valueEl.textContent = parts.label;
      trigger.title = parts.label.length > 28 ? parts.label : '';
      trigger.classList.toggle('is-placeholder', !!opt && opt.value === '' && select.selectedIndex === 0);
      trigger.disabled = select.disabled;
      var invalid = select.classList.contains('field-error');
      trigger.classList.toggle('is-invalid', invalid);
      if (invalid) trigger.setAttribute('aria-invalid', 'true'); else trigger.removeAttribute('aria-invalid');
      if (panel) build();
    }

    // Programmatic `select.value = x` (used by the page scripts) has no event; intercept it.
    Object.defineProperty(select, 'value', {
      configurable: true,
      get: function () { return VALUE.get.call(this); },
      set: function (v) { VALUE.set.call(this, v); sync(); }
    });
    select.addEventListener('change', sync);
    if ('MutationObserver' in window) {
      new MutationObserver(sync).observe(select, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'disabled', 'label'] });
    }
    // select.focus() (e.g. validation) or a <label> click lands on the hidden select -> hand over
    select.addEventListener('focus', function () { trigger.focus(); });

    // ── panel ──
    function build() {
      var html = '';
      Array.prototype.forEach.call(select.options, function (opt, i) {
        var p = labelOf(opt), sel = i === select.selectedIndex;
        html += '<li class="gs-opt' + (opt.value === '' && i === 0 ? ' is-placeholder' : '') + '" role="option" id="' + id + '-o' + i + '" data-i="' + i + '"' +
          ' aria-selected="' + sel + '"' + (opt.disabled ? ' aria-disabled="true"' : '') + (p.label.length > 40 ? ' title="' + esc(p.label) + '"' : '') + '>' +
          '<span class="gs-label">' + esc(p.label) + '</span>' + (p.count ? '<span class="gs-count">' + p.count + '</span>' : '<span></span>') + CHECK + '</li>';
      });
      panel.innerHTML = html;
      if (active >= 0) markActive(active, false);
    }

    function markActive(i, scroll) {
      var items = panel.children;
      if (active >= 0 && items[active]) items[active].classList.remove('is-active');
      active = i;
      var el = items[i];
      if (!el) { trigger.removeAttribute('aria-activedescendant'); return; }
      el.classList.add('is-active');
      trigger.setAttribute('aria-activedescendant', el.id);
      if (scroll !== false) {
        var top = el.offsetTop, bottom = top + el.offsetHeight;
        if (top - 6 < panel.scrollTop) panel.scrollTop = Math.max(0, top - 6);
        else if (bottom + 6 > panel.scrollTop + panel.clientHeight) panel.scrollTop = bottom + 6 - panel.clientHeight;
      }
    }

    function enabledFrom(start, dir) {
      var n = select.options.length;
      for (var k = 0, i = start; k < n; k++, i += dir) {
        if (i < 0 || i >= n) return -1;
        if (!select.options[i].disabled) return i;
      }
      return -1;
    }

    function position() {
      if (!panel) return;
      var keep = panel.scrollTop;
      var r = trigger.getBoundingClientRect();
      var vw = document.documentElement.clientWidth, vh = window.innerHeight, m = 8, gap = 6;
      panel.style.minWidth = Math.round(r.width) + 'px';
      panel.style.maxWidth = Math.min(448, vw - 2 * m) + 'px';
      panel.style.maxHeight = 'none';
      panel.style.left = '0px'; panel.style.top = '0px';
      var natural = Math.min(panel.scrollHeight + 2, 340);
      var below = vh - r.bottom - m - gap, above = r.top - m - gap;
      var flip = below < Math.min(natural, 200) && above > below;
      var room = flip ? above : below;
      var h = Math.max(96, Math.min(natural, room));
      panel.style.maxHeight = h + 'px';
      var w = panel.offsetWidth, ph = panel.offsetHeight;
      panel.style.left = Math.round(Math.min(Math.max(m, r.left), Math.max(m, vw - m - w))) + 'px';
      panel.style.top = Math.round(flip ? r.top - gap - ph : r.bottom + gap) + 'px';
      panel.setAttribute('data-place', flip ? 'top' : 'bottom');
      panel.scrollTop = keep;
    }
    function onScroll(e) { if (panel && e.target === panel) return; position(); }

    function open() {
      if (select.disabled || trigger.getAttribute('aria-expanded') === 'true') return;
      if (current && current !== api) current.close(false);
      current = api;
      panel = document.createElement('ul');
      panel.className = 'gs-panel';
      panel.id = listId;
      panel.setAttribute('role', 'listbox');
      panel.setAttribute('aria-label', name);
      panel.addEventListener('mousedown', function (e) { e.preventDefault(); });   // keep focus on the trigger
      panel.addEventListener('click', function (e) {
        var li = e.target.closest ? e.target.closest('.gs-opt') : null;
        if (li) choose(Number(li.getAttribute('data-i')));
      });
      panel.addEventListener('mousemove', function (e) {
        var li = e.target.closest ? e.target.closest('.gs-opt') : null;
        if (li && !li.classList.contains('is-active') && li.getAttribute('aria-disabled') !== 'true') markActive(Number(li.getAttribute('data-i')), false);
      });
      active = select.selectedIndex >= 0 ? select.selectedIndex : enabledFrom(0, 1);
      build();
      document.body.appendChild(panel);
      position();
      trigger.setAttribute('aria-expanded', 'true');
      // Safari does not focus a <button> on click; keys (Escape, arrows) must reach the trigger
      if (document.activeElement !== trigger) trigger.focus({ preventScroll: true });
      markActive(active, true);
      requestAnimationFrame(function () { if (panel) panel.classList.add('is-open'); });
      document.addEventListener('pointerdown', onOutside, true);
      window.addEventListener('resize', position);
      window.addEventListener('scroll', onScroll, true);
    }

    function close(refocus) {
      if (trigger.getAttribute('aria-expanded') !== 'true') return;
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      document.removeEventListener('pointerdown', onOutside, true);
      window.removeEventListener('resize', position);
      window.removeEventListener('scroll', onScroll, true);
      var p = panel; panel = null; active = -1;
      if (current === api) current = null;
      if (p) {
        p.classList.remove('is-open');
        if (reduceMotion) p.remove(); else setTimeout(function () { p.remove(); }, 160);
      }
      if (refocus !== false) trigger.focus();
    }

    function choose(i) {
      var opt = select.options[i];
      if (!opt || opt.disabled) return;
      var changed = select.selectedIndex !== i;
      select.selectedIndex = i;
      sync();
      close(true);
      if (changed) {
        select.dispatchEvent(new Event('input', { bubbles: true }));
        select.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }

    function onOutside(e) {
      if (panel && (panel.contains(e.target) || trigger.contains(e.target))) return;
      close(false);
    }

    trigger.addEventListener('click', function () { if (trigger.getAttribute('aria-expanded') === 'true') close(true); else open(); });

    trigger.addEventListener('keydown', function (e) {
      var isOpen = trigger.getAttribute('aria-expanded') === 'true';
      var k = e.key;
      if (!isOpen) {
        if (k === 'ArrowDown' || k === 'ArrowUp' || k === 'Enter' || k === ' ') { e.preventDefault(); open(); return; }
      } else {
        if (k === 'Escape') { e.preventDefault(); e.stopPropagation(); close(true); return; }
        if (k === 'Tab') { close(false); return; }
        if (k === 'Enter' || k === ' ') { e.preventDefault(); if (active >= 0) choose(active); return; }
        var n = select.options.length, next = -1;
        if (k === 'ArrowDown') next = enabledFrom(Math.min(n - 1, active + 1), 1);
        else if (k === 'ArrowUp') next = enabledFrom(Math.max(0, active - 1), -1);
        else if (k === 'Home') next = enabledFrom(0, 1);
        else if (k === 'End') next = enabledFrom(n - 1, -1);
        else if (k === 'PageDown') next = enabledFrom(Math.min(n - 1, active + 8), -1) ;
        else if (k === 'PageUp') next = enabledFrom(Math.max(0, active - 8), 1);
        if (next >= 0 || k === 'ArrowDown' || k === 'ArrowUp' || k === 'Home' || k === 'End' || k === 'PageDown' || k === 'PageUp') {
          e.preventDefault();
          if (next >= 0) markActive(next, true);
          return;
        }
      }
      // type-ahead: jump to the next option starting with the typed text
      if (k.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey && k !== ' ') {
        typed += k.toLowerCase();
        clearTimeout(typedTimer); typedTimer = setTimeout(function () { typed = ''; }, 600);
        var start = isOpen ? active : select.selectedIndex;
        var order = [];
        for (var j = 1; j <= select.options.length; j++) order.push((start + j) % select.options.length);
        if (typed.length > 1) order.unshift(start);
        for (var q = 0; q < order.length; q++) {
          var o = select.options[order[q]];
          if (!o.disabled && labelOf(o).label.toLowerCase().indexOf(typed) === 0) {
            if (isOpen) markActive(order[q], true); else { select.selectedIndex = order[q]; sync(); select.dispatchEvent(new Event('input', { bubbles: true })); select.dispatchEvent(new Event('change', { bubbles: true })); }
            break;
          }
        }
      }
    });

    var api = { close: close, open: open, sync: sync, trigger: trigger };
    select._gs = api;
    sync();
    return api;
  }

  function init() { Array.prototype.forEach.call(document.querySelectorAll('select'), enhance); }
  window.GHSelect = { enhance: enhance, init: init };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();

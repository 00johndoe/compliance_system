import { readFileSync } from 'node:fs';
import { test, expect, eq, sleep } from './harness.mjs';

const DATA = JSON.parse(readFileSync(new URL('../../data/ghana-requirements.json', import.meta.url), 'utf8'));
const groupLinks = (id) => DATA.requirements.filter((r) => r.group === id).reduce((n, r) => n + r.iso27002Links.length, 0);

const T = (i) => `document.querySelectorAll('.gs-trigger')[${i}]`;
const PANEL = "(() => { const p = document.querySelector('.gs-panel'); if (!p) return null; const r = p.getBoundingClientRect(); return { l: Math.round(r.left), t: Math.round(r.top), r: Math.round(r.right), b: Math.round(r.bottom), vw: document.documentElement.clientWidth, vh: innerHeight, place: p.dataset.place }; })()";
const inside = (r) => r && r.l >= 0 && r.t >= 0 && r.r <= r.vw && r.b <= r.vh;

async function open(page, base, width = 1280, height = 900) {
  await page.goto(base, '/mapping.html', { width, height });
  await page.waitFor("document.querySelectorAll('.gs-trigger').length === 3 && document.querySelectorAll('#tableBody tr[data-i]').length > 0");
}

test('dropdown: native selects are replaced by accessible comboboxes and stay the source of truth', async ({ page, base }) => {
  await open(page, base);
  const info = await page.eval(`(() => { const t = ${T(0)}; const n = document.getElementById('groupFilter').getBoundingClientRect();
    return { role: t.getAttribute('role'), popup: t.getAttribute('aria-haspopup'), expanded: t.getAttribute('aria-expanded'), name: t.getAttribute('aria-label'), text: t.textContent.trim(), nativeSize: [Math.round(n.width), Math.round(n.height)] }; })()`);
  eq(info, { role: 'combobox', popup: 'listbox', expanded: 'false', name: 'Requirement group', text: 'All groups', nativeSize: [1, 1] });
});

test('dropdown: opens with counts, marks the selected option, and selecting applies the filter', async ({ page, base }) => {
  await open(page, base);
  await page.eval(`${T(0)}.click(); true`);
  await page.waitFor("document.querySelector('.gs-panel.is-open')");
  const list = await page.eval(`({ options: document.querySelectorAll('.gs-opt').length, counts: [...document.querySelectorAll('.gs-count')].map((c) => c.textContent).join(), selected: document.querySelector('.gs-opt[aria-selected=true]').textContent.trim(), labelsHaveNoCount: [...document.querySelectorAll('.gs-label')].every((l) => !/\\(\\d+\\)/.test(l.textContent)) })`);
  eq(list, { options: 1 + DATA.groups.length, counts: DATA.groups.map((g) => groupLinks(g.id)).join(','), selected: 'All groups', labelsHaveNoCount: true });
  await page.eval("document.querySelectorAll('.gs-opt')[3].click(); true");
  await page.waitFor(`document.querySelectorAll('#tableBody tr[data-i]').length === ${groupLinks('SEC')}`);
  eq(await page.eval(`[groupFilter.value, ${T(0)}.textContent.trim(), !document.querySelector('.gs-panel.is-open')]`), ['SEC', 'Security safeguards & risk', true]);
  eq(await page.eval(`document.activeElement === ${T(0)}`), true, 'focus returns to the trigger');
});

test('dropdown: full keyboard support (arrows, Enter, Space, Home/End, Escape, type-ahead)', async ({ page, base }) => {
  await open(page, base);
  await page.eval(`${T(1)}.focus(); true`);
  await page.key('ArrowDown', 'ArrowDown', 40);
  await page.waitFor(`${T(1)}.getAttribute('aria-expanded') === 'true'`);
  await page.key('ArrowDown', 'ArrowDown', 40); await page.key('ArrowDown', 'ArrowDown', 40);
  expect(await page.eval(`!!${T(1)}.getAttribute('aria-activedescendant')`), 'aria-activedescendant tracks the active option');
  await page.key('Enter', 'Enter', 13);
  await page.waitFor("document.getElementById('themeFilter').value === 'People'");
  await page.key('ArrowDown', 'ArrowDown', 40);
  await page.key('Escape', 'Escape', 27);
  await page.waitFor(`${T(1)}.getAttribute('aria-expanded') === 'false'`);
  eq(await page.eval(`[themeFilter.value, document.activeElement === ${T(1)}]`), ['People', true], 'Escape closes without changing the value and keeps focus');
  await page.eval(`${T(2)}.focus(); true`);
  await page.key(' ', 'Space', 32);
  await page.key('End', 'End', 35); await page.key('Enter', 'Enter', 13);
  await page.waitFor("document.getElementById('sortSelect').value === 'iso'");
  await page.eval(`${T(0)}.focus(); true`);
  await page.key('ArrowDown', 'ArrowDown', 40); await page.key('p', 'KeyP', 80); await page.key('Enter', 'Enter', 13);
  await page.waitFor("document.getElementById('groupFilter').value === 'PPL'");
});

test('dropdown: closes on outside click; programmatic value changes update the trigger', async ({ page, base }) => {
  await open(page, base);
  await page.eval(`${T(0)}.click(); true`);
  await page.waitFor("document.querySelector('.gs-panel.is-open')");
  await page.mouseClick(5, 5);
  await page.waitFor(`${T(0)}.getAttribute('aria-expanded') === 'false'`);
  await page.eval("groupFilter.value = 'GOV'; themeFilter.value = 'People'; true");   // programmatic writes, as the page's own code does
  eq(await page.eval("[...document.querySelectorAll('.gs-trigger')].slice(0, 2).map((t) => t.textContent.trim())"), ['Governance & accountability', 'People'], 'triggers follow programmatic value changes');
  await page.eval("groupFilter.dispatchEvent(new Event('change', { bubbles: true })); true");                  // now register the filter with the page
  await page.waitFor('clearBtn.disabled === false');
  await page.eval('clearBtn.click(); true');
  await page.waitFor(`${T(0)}.textContent.trim() === 'All groups'`);
});

test('dropdown: the panel stays inside the viewport at every width, flipping above near the bottom', async ({ page, base }) => {
  const bad = [];
  for (const [w, h] of [[320, 640], [390, 844], [768, 1024], [1280, 800]]) {
    await open(page, base, w, h);
    for (let i = 0; i < 3; i++) {
      await page.eval(`(() => { const t = ${T(i)}; window.scrollTo(0, 0); t.scrollIntoView({ block: 'start' }); window.scrollBy(0, -90); return true; })()`);
      await page.eval(`${T(i)}.click(); true`);
      await page.waitFor("document.querySelector('.gs-panel.is-open')");
      let r = await page.eval(PANEL);
      const noOverflow = await page.eval('document.documentElement.scrollWidth <= document.documentElement.clientWidth');
      if (!inside(r) || !noOverflow) bad.push(`${w}px #${i} top ${JSON.stringify(r)}`);
      await page.eval(`${T(i)}.click(); true`); await page.waitFor("!document.querySelector('.gs-panel')");
      // trigger near the bottom edge -> should flip above and still fit
      await page.eval(`(() => { const t = ${T(i)}; window.scrollTo(0, t.getBoundingClientRect().top + scrollY - (innerHeight - 70)); return true; })()`);
      await page.eval(`${T(i)}.click(); true`);
      await page.waitFor("document.querySelector('.gs-panel.is-open')");
      r = await page.eval(PANEL);
      if (!inside(r)) bad.push(`${w}px #${i} bottom ${JSON.stringify(r)}`);
      if (i === 0 && (w === 390 || w === 1280)) eq(r.place, 'top', `${w}px: opens upward when there is no room below`);
      await page.eval(`${T(i)}.click(); true`); await page.waitFor("!document.querySelector('.gs-panel')");
    }
  }
  eq(bad, [], 'dropdown panels outside the viewport');
});

test('dropdown: a long list scrolls inside the panel and keeps its position', async ({ page, base }) => {
  await open(page, base, 390, 500);
  await page.eval("const s = document.getElementById('sortSelect'); for (let i = 0; i < 40; i++) { const o = document.createElement('option'); o.value = 'o' + i; o.textContent = 'Extra option ' + i; s.appendChild(o); } true");
  await page.eval(`(() => { const t = ${T(2)}; window.scrollTo(0, t.getBoundingClientRect().top + scrollY - 120); return true; })()`);
  await page.eval(`${T(2)}.click(); true`);
  await page.waitFor("document.querySelector('.gs-panel.is-open')");
  await page.eval("document.querySelector('.gs-panel').scrollTop = 300; true");
  await sleep(400);
  eq(await page.eval("Math.round(document.querySelector('.gs-panel').scrollTop)"), 300, 'scroll position is kept');
  await page.key('End', 'End', 35);
  expect(await page.eval("(() => { const p = document.querySelector('.gs-panel'), a = p.querySelector('.is-active'); const pr = p.getBoundingClientRect(), ar = a.getBoundingClientRect(); return a.textContent.includes('Extra option 39') && ar.top >= pr.top - 1 && ar.bottom <= pr.bottom + 1; })()"), 'End brings the last option into view');
});

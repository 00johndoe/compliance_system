import { test, expect, eq, sleep } from './harness.mjs';
import { SEED } from './fixtures.mjs';

const rows = "document.querySelectorAll('#tableBody tr[data-i]').length";
const setSelect = (id, v) => `(() => { const s = document.getElementById('${id}'); s.value = ${JSON.stringify(v)}; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`;
const setSearch = (v) => `(() => { const i = document.getElementById('searchInput'); i.value = ${JSON.stringify(v)}; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;

async function open(page, base, qs = '', width = 1280) {
  await page.goto(base, '/mapping.html' + qs, { width });
  await page.waitFor(`${rows} > 0`);
}

test('mapping: filters, search and sorting', async ({ page, base }) => {
  await open(page, base);
  eq(await page.eval(rows), 47, 'all mappings shown');
  await page.eval(setSelect('domainFilter', 'Incident Response'));
  await page.waitFor(`${rows} === 9`);
  await page.eval(setSelect('themeFilter', 'Technological'));
  await page.waitFor(`${rows} === 2`);
  expect(await page.eval("[...document.querySelectorAll('#tableBody tr[data-i]')].every((r) => r.children[2].textContent.trim() === 'Incident Response' && r.children[4].textContent.trim() === 'Technological')"), 'domain + theme filters combine');
  await page.eval("clearBtn.click(); true");
  await page.waitFor(`${rows} === 47`);
  eq(await page.eval('clearBtn.disabled'), true, 'clear is disabled with no filters');

  await page.eval(setSearch('incident'));
  await page.waitFor(`${rows} === 10`);
  expect(await page.eval("document.querySelectorAll('#tableBody mark').length > 0"), 'matches are highlighted');
  await page.eval(setSearch('<img src=x onerror=alert(1)>'));
  await page.waitFor("!!document.querySelector('#tableBody [data-clear]')");
  eq(await page.eval("document.querySelectorAll('#tableBody img').length"), 0, 'search text is never injected as HTML');
  eq(await page.eval('exportBtn.disabled'), true, 'export is disabled when nothing matches');
  await page.eval(setSearch(''));

  await page.eval(setSelect('sortSelect', 'iso'));
  await page.waitFor("document.querySelector('#tableBody tr[data-i] td:nth-child(4)').textContent.startsWith('5.1 ')");
  eq(await page.eval("[...document.querySelectorAll('#tableBody tr[data-i]')].slice(0, 4).map((r) => r.children[3].textContent.trim().split(' ')[0])"), ['5.1', '5.2', '5.3', '5.4'], 'ISO numbers sort numerically');
  await page.eval(setSelect('sortSelect', 'alignment'));
  await page.waitFor("document.querySelector('#tableBody tr[data-i] td:nth-child(6)').textContent.trim() === 'Strong'");
});

test('mapping: stat cards filter, and the URL keeps and restores state', async ({ page, base }) => {
  await open(page, base);
  await page.eval("document.querySelector('.stat-btn[data-align=strong]').click(); true");
  await page.waitFor(`${rows} === 21`);
  eq(await page.eval('location.search'), '?a=strong');
  await page.eval("document.querySelector('.stat-btn[data-align=strong]').click(); true");
  await page.waitFor(`${rows} === 47`);
  await open(page, base, '?a=partial&d=Capacity+Building&s=ncf');
  eq(await page.eval(`[${rows}, domainFilter.value, document.querySelector('.filter-btn.active').textContent.trim()]`), [3, 'Capacity Building', 'Partial'], 'state restored from the URL');
  await open(page, base, '?a=bogus&d=NotADomain&v=nope&s=evil');
  eq(await page.eval(rows), 47, 'invalid parameters are ignored');
});

test('mapping: grouped and coverage views', async ({ page, base }) => {
  await open(page, base);
  await page.eval("document.getElementById('tab-grouped').click(); true");
  eq(await page.eval("[document.querySelectorAll('#view-grouped details.group').length, document.querySelectorAll('#view-grouped .map-item').length]"), [6, 47]);
  await page.eval("document.getElementById('tab-coverage').click(); true");
  const cov = await page.eval(`(() => { const r = [...document.querySelectorAll('#covBody tr')];
    return { rows: r.length, total: r.reduce((s, x) => s + (parseInt(x.lastElementChild.textContent, 10) || 0), 0), physicalEmpty: r.every((x) => x.children[3].textContent.trim() === '—') }; })()`);
  eq(cov, { rows: 6, total: 47, physicalEmpty: true }, 'coverage totals 47 mappings; no NCF control maps to the Physical theme');
  await page.eval("document.querySelector('.cov-cell[data-cov-d=\"Governance & Leadership\"][data-cov-t=\"Organizational\"]').click(); true");
  await page.waitFor(`!document.getElementById('view-table').hidden && ${rows} === 9`);
  eq(await page.eval('[domainFilter.value, themeFilter.value]'), ['Governance & Leadership', 'Organizational']);
});

test('mapping: detail panel shows related controls and the user\'s scores, and closes with Escape', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  await open(page, base);
  await page.eval("document.querySelector('#tableBody .link-btn').focus(); document.querySelector('#tableBody .link-btn').click(); true");
  await page.waitFor("document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("document.getElementById('detailSheet').getAttribute('aria-hidden')"), 'false');
  expect(await page.waitFor("document.getElementById('detailSheet').contains(document.activeElement)"), 'focus moves into the panel');
  eq(await page.eval("document.querySelectorAll('#sheetBody .meter').length"), 2, 'domain + theme score meters (assessment present)');
  await page.key('Escape', 'Escape', 27);
  await page.waitFor("!document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("document.activeElement.className"), 'link-btn', 'focus returns to the control that opened it');
  await page.eval("(() => { const i = mappings.findIndex((m) => m.iso.startsWith('5.35')); document.querySelector('#tableBody tr[data-i=\"' + i + '\"]').click(); return true; })()");
  await page.waitFor("document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("[...document.querySelectorAll('#sheetBody .sheet-block')].find((b) => b.textContent.includes('Other NCF')).querySelectorAll('li').length"), 2, 'other NCF controls mapped to ISO 5.35');
});

test('mapping: CSV export matches the filtered rows and neutralises spreadsheet formulas', async ({ page, base }) => {
  await open(page, base);
  await page.eval(`window.Blob = (function (O) { return function (p, o) { window.__csv = p.join(''); return new O(p, o); }; })(window.Blob); true`);
  await page.eval(setSearch('legis'));
  await page.waitFor(`${rows} === 2`);
  await page.eval('exportBtn.click(); true');
  await page.waitFor('!!window.__csv');
  const csv = await page.eval(`(() => { const t = window.__csv; const lines = t.slice(1).split('\\r\\n'); return { rows: lines.length - 1, bom: t.charCodeAt(0) === 0xFEFF, header: lines[0] }; })()`);
  eq(csv, { rows: 2, bom: true, header: '"#","Ghana NCF Control","NCF Domain","ISO 27002 Control","ISO Theme","Alignment"' });
  eq(await page.eval("csvCell('=cmd|calc')"), '"\'=cmd|calc"', 'formula injection guard');
});

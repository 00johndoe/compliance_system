import { readFileSync } from 'node:fs';
import { test, expect, eq, sleep } from './harness.mjs';
import { SEED } from './fixtures.mjs';

// Expected figures are derived from the real dataset, so the test also proves the page shows all of it.
const DATA = JSON.parse(readFileSync(new URL('../../data/ghana-requirements.json', import.meta.url), 'utf8'));
const THEME_OF = (id) => ({ 5: 'Organizational', 6: 'People', 7: 'Physical', 8: 'Technological' }[id.split('.')[0]]);
const LINKS = DATA.requirements.flatMap((r) => r.iso27002Links.map((iso) => ({ r, iso })));
const count = (fn) => LINKS.filter(fn).length;
const groupName = (id) => DATA.groups.find((g) => g.id === id).name;

const rows = "document.querySelectorAll('#tableBody tr[data-i]').length";
const setSelect = (id, v) => `(() => { const s = document.getElementById('${id}'); s.value = ${JSON.stringify(v)}; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`;
const setSearch = (v) => `(() => { const i = document.getElementById('searchInput'); i.value = ${JSON.stringify(v)}; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;

async function open(page, base, qs = '', width = 1280) {
  await page.goto(base, '/mapping.html' + qs, { width });
  await page.waitFor(`${rows} > 0`);
}

test('mapping: shows every proposed link, unrated', async ({ page, base }) => {
  await open(page, base);
  eq(await page.eval(rows), LINKS.length, 'one row per requirement/ISO link');
  eq(await page.eval("[cntLinks.textContent, cntReq.textContent, cntIso.textContent]"), [String(LINKS.length), String(DATA.requirements.length), String(new Set(LINKS.map((l) => l.iso)).size)], 'stat cards');
  const text = await page.eval("document.body.innerText");
  eq(await page.eval("!!document.getElementById('proposedNotice')"), false, 'no validation banner');
  expect(!/Strong|Moderate|Partial/.test(text), 'no alignment ratings appear anywhere on the page');
  eq(await page.eval("document.querySelectorAll('[data-align]').length"), 0, 'no alignment filters');
});

test('mapping: filters, search and sorting', async ({ page, base }) => {
  await open(page, base);
  await page.eval(setSelect('groupFilter', 'INC'));
  await page.waitFor(`${rows} === ${count((l) => l.r.group === 'INC')}`);
  await page.eval(setSelect('themeFilter', 'Organizational'));
  const both = count((l) => l.r.group === 'INC' && THEME_OF(l.iso) === 'Organizational');
  await page.waitFor(`${rows} === ${both}`);
  expect(await page.eval(`[...document.querySelectorAll('#tableBody tr[data-i]')].every((r) => r.children[2].textContent.trim() === ${JSON.stringify(groupName('INC'))} && r.children[5].textContent.trim() === 'Organizational')`), 'group + theme filters combine');
  await page.eval('clearBtn.click(); true');
  await page.waitFor(`${rows} === ${LINKS.length}`);
  eq(await page.eval('clearBtn.disabled'), true, 'clear is disabled with no filters');

  await page.eval("document.querySelector('#tierChips [data-tier=\"2\"]').click(); true");
  await page.waitFor(`${rows} === ${count((l) => l.r.tier === '2')}`);
  eq(await page.eval('location.search'), '?w=2', 'tier chip is kept in the URL');
  await page.eval("document.querySelector('#tierChips [data-tier=\"all\"]').click(); true");
  await page.waitFor(`${rows} === ${LINKS.length}`);

  await page.eval(setSearch('breach'));
  await page.waitFor(`${rows} > 0 && ${rows} < ${LINKS.length}`);
  expect(await page.eval("document.querySelectorAll('#tableBody mark').length > 0"), 'matches are highlighted');
  await page.eval(setSearch('<img src=x onerror=alert(1)>'));
  await page.waitFor("!!document.querySelector('#tableBody [data-clear]')");
  eq(await page.eval("document.querySelectorAll('#tableBody img').length"), 0, 'search text is never injected as HTML');
  eq(await page.eval('exportBtn.disabled'), true, 'export is disabled when nothing matches');
  await page.eval(setSearch(''));

  await page.eval(setSelect('sortSelect', 'iso'));
  await page.waitFor("document.querySelector('#tableBody tr[data-i] td:nth-child(5)').textContent.startsWith('5.1 ')");
  const nums = await page.eval("[...document.querySelectorAll('#tableBody tr[data-i]')].map((r) => r.children[4].textContent.trim().split(' ')[0].split('.').map(Number))");
  expect(nums.every((n, i) => i === 0 || nums[i - 1][0] < n[0] || (nums[i - 1][0] === n[0] && nums[i - 1][1] <= n[1])), 'ISO numbers sort numerically (5.2 before 5.10)');
  await page.eval(setSelect('sortSelect', 'req'));
  await page.waitFor("document.querySelector('#tableBody tr[data-i] td:nth-child(2)').textContent.startsWith('T1A-01')");
});

test('mapping: the URL keeps and restores state (including the dashboard links)', async ({ page, base }) => {
  await open(page, base, '?w=1B&g=SEC&s=req');
  eq(await page.eval(`[${rows}, groupFilter.value, document.querySelector('#tierChips .active').textContent.trim()]`), [count((l) => l.r.tier === '1B' && l.r.group === 'SEC'), 'SEC', 'Personal data'], 'state restored from the URL');
  await open(page, base, '?g=DPP');
  eq(await page.eval(rows), count((l) => l.r.group === 'DPP'), 'dashboard group link (?g=)');
  await open(page, base, '?t=Technological');
  eq(await page.eval(rows), count((l) => THEME_OF(l.iso) === 'Technological'), 'dashboard theme link (?t=)');
  await open(page, base, '?g=NOPE&w=9&t=Evil&v=nope&s=evil');
  eq(await page.eval(rows), LINKS.length, 'invalid parameters are ignored');
});

test('mapping: grouped and coverage views', async ({ page, base }) => {
  await open(page, base);
  await page.eval("document.getElementById('tab-grouped').click(); true");
  const groupsWithLinks = DATA.groups.filter((g) => count((l) => l.r.group === g.id) > 0).length;
  eq(await page.eval("[document.querySelectorAll('#view-grouped details.group').length, document.querySelectorAll('#view-grouped .map-item').length]"), [groupsWithLinks, LINKS.length]);
  await page.eval("document.getElementById('tab-coverage').click(); true");
  const cov = await page.eval(`(() => { const r = [...document.querySelectorAll('#covBody tr')];
    return { rows: r.length, total: r.reduce((s, x) => s + (parseInt(x.lastElementChild.textContent, 10) || 0), 0) }; })()`);
  eq(cov, { rows: DATA.groups.length, total: LINKS.length }, 'coverage rows and total links');
  expect(await page.eval("/T2-21/.test(covFoot.textContent)"), 'the requirement with no ISO link is called out');
  await page.eval("document.querySelector('.cov-cell[data-cov-g=\"INC\"][data-cov-t=\"Organizational\"]').click(); true");
  await page.waitFor(`!document.getElementById('view-table').hidden && ${rows} === ${count((l) => l.r.group === 'INC' && THEME_OF(l.iso) === 'Organizational')}`);
  eq(await page.eval('[groupFilter.value, themeFilter.value]'), ['INC', 'Organizational']);
});

test('mapping: detail panel shows the requirement, its source, caveats and the user\'s scores, and closes with Escape', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  await open(page, base);
  await page.eval("document.querySelector('#tableBody .link-btn').focus(); document.querySelector('#tableBody .link-btn').click(); true");
  await page.waitFor("document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("document.getElementById('detailSheet').getAttribute('aria-hidden')"), 'false');
  expect(await page.waitFor("document.getElementById('detailSheet').contains(document.activeElement)"), 'focus moves into the panel');
  const sheet = await page.eval("sheetBody.innerText");
  expect(/T1A-01/.test(sheet) && /Act 1038 s\.47/.test(sheet), 'requirement and its citation');
  expect(/Proposed/.test(sheet) && /not been validated/.test(sheet), 'status is stated');
  expect(/institution/.test(sheet), 'the "institution" caveat is shown for T1A-01');
  expect(/This requirement: Partially implemented/.test(sheet), 'the user\'s answer for this requirement (SEED: 2.5)');
  eq(await page.eval("document.querySelectorAll('#sheetBody .meter').length"), 2, 'group + ISO theme score meters');
  await page.key('Escape', 'Escape', 27);
  await page.waitFor("!document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("document.activeElement.className"), 'link-btn', 'focus returns to the control that opened it');

  const others = count((l) => l.iso === '5.24') - 1;
  await page.eval("(() => { const i = mappings.findIndex((m) => m.iso === '5.24'); document.querySelector('#tableBody tr[data-i=\"' + i + '\"]').click(); return true; })()");
  await page.waitFor("document.getElementById('detailSheet').classList.contains('open')");
  eq(await page.eval("[...document.querySelectorAll('#sheetBody .sheet-block')].find((b) => b.textContent.includes('Other requirements')).querySelectorAll('li').length"), others, 'other requirements linked to ISO 5.24');
});

test('mapping: CSV export matches the filtered rows and neutralises spreadsheet formulas', async ({ page, base }) => {
  await open(page, base);
  await page.eval(`window.Blob = (function (O) { return function (p, o) { window.__csv = p.join(''); return new O(p, o); }; })(window.Blob); true`);
  await page.eval(setSearch('T1A-01'));
  await page.waitFor(`${rows} === ${count((l) => l.r.id === 'T1A-01')}`);
  await page.eval('exportBtn.click(); true');
  await page.waitFor('!!window.__csv');
  const csv = await page.eval(`(() => { const t = window.__csv; const lines = t.slice(1).split('\\r\\n'); return { rows: lines.length - 1, bom: t.charCodeAt(0) === 0xFEFF, header: lines[0], status: /Proposed \\(not validated\\)/.test(lines[1]) }; })()`);
  eq(csv, { rows: count((l) => l.r.id === 'T1A-01'), bom: true, header: '"#","Requirement ID","Requirement","Group","Applies to","Source","ISO 27002 Control","ISO Title","ISO Theme","Status"', status: true });
  eq(await page.eval("csvCell('=cmd|calc')"), '"\'=cmd|calc"', 'formula injection guard');
});

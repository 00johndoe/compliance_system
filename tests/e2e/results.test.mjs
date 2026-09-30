import { test, expect, eq } from './harness.mjs';
import { SEED } from './fixtures.mjs';

async function report(page, base, width = 1280, height = 900) {
  await page.seedAssessment(base, SEED);
  await page.goto(base, '/results.html', { width, height });
  await page.waitFor("!document.getElementById('resultsContent').classList.contains('hidden') && document.querySelectorAll('#detailBody tr[data-row]').length > 0");
}
const visible = "[...document.querySelectorAll('#detailBody tr[data-row]')].filter((r) => getComputedStyle(r).display !== 'none')";

test('report: the score matches the dashboard and the controls table filters by status', async ({ page, base }) => {
  await report(page, base);
  const score = await page.eval('coverOverallScore.textContent');
  await page.eval("(() => { const s = document.getElementById('controlsFilter'); s.value = 'critical'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()");
  await page.waitFor(`${visible}.every((r) => r.dataset.status === 'critical') && ${visible}.length > 0`);
  await page.eval("(() => { const i = document.getElementById('controlsSearch'); i.value = 'zzzzqq'; i.oninput({ target: i }); return true; })()");
  await page.waitFor("!!document.getElementById('emptyStateRow')");
  await page.goto(base, '/index.html');
  eq(await page.eval("statusPanel.querySelector('.ring-in b').textContent"), score, 'dashboard and report show the same overall score');
});

test('report: on a phone the controls table becomes labelled cards and the heat map scrolls inside its panel', async ({ page, base }) => {
  await report(page, base, 390, 844);
  eq(await page.eval("getComputedStyle(document.querySelector('.mobile-topbar')).display"), 'flex', 'mobile header shown');
  eq(await page.eval("getComputedStyle(document.querySelector('.sidebar')).display"), 'none', 'desktop sidebar hidden');
  eq(await page.eval("document.querySelector('#detailBody td:nth-child(3)').dataset.label"), 'Score', 'cells carry labels for the card layout');
  eq(await page.eval("getComputedStyle(document.querySelector('#detailBody tr')).display"), 'block', 'rows are cards');
  const heat = await page.eval("(() => { const p = document.querySelector('.risk-matrix-panel'); return { scrolls: p.scrollWidth > p.clientWidth, pageFits: document.documentElement.scrollWidth <= document.documentElement.clientWidth }; })()");
  eq(heat, { scrolls: true, pageFits: true }, 'the heat map scrolls inside its own panel, not the page');
});

test('report: mobile menu lists the site pages and the report sections, and closes when a link is used', async ({ page, base }) => {
  await report(page, base, 390, 844);
  await page.eval("document.getElementById('menuBtn').click(); true");
  await page.waitFor("document.getElementById('drawer').classList.contains('open')");
  eq(await page.eval("[...document.querySelectorAll('#drawer nav[aria-label=\"Site pages\"] a')].map((a) => a.textContent.trim())"), ['Dashboard', 'Control Mapping', 'Assessment', 'Results', 'Gap Analysis']);
  eq(await page.eval("document.querySelectorAll('#drawer nav[aria-label=\"Report sections\"] a').length"), 7);
  await page.eval("document.querySelector('#drawer a[href=\"#risk-matrix\"]').click(); true");
  await page.waitFor("!document.getElementById('drawer').classList.contains('open')");
});

test('report: printing hides the mobile header and drawer', async ({ page, base }) => {
  await report(page, base, 794, 900);
  await page.send('Emulation.setEmulatedMedia', { media: 'print' });
  const hidden = await page.eval("['.mobile-topbar', '.mobile-drawer', '.mobile-overlay', '.sidebar'].map((s) => getComputedStyle(document.querySelector(s)).display)");
  await page.send('Emulation.setEmulatedMedia', { media: 'screen' });
  eq(hidden, ['none', 'none', 'none', 'none']);
});

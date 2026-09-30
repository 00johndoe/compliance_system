import { test, expect, eq } from './harness.mjs';
import { SEED, ALL_PAGES, MAIN_PAGES } from './fixtures.mjs';

test('security: pages contact no third-party hosts (all assets are self-hosted)', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  page.hosts.clear();
  for (const p of ALL_PAGES) await page.goto(base, `/${p}.html`);
  const own = new URL(base).host;
  const other = [...page.hosts].filter((h) => h && h !== own);
  eq(other, [], 'third-party hosts contacted');
});

test('pages load without JavaScript errors or console errors', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  page.problems.length = 0;
  for (const p of ALL_PAGES) await page.goto(base, `/${p}.html`);
  eq(page.problems, [], 'errors during page loads');
});

test('assets load: icon font, Inter, and Chart.js 4.5.1 (pinned) on the report', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  await page.goto(base, '/index.html');
  expect(await page.eval("document.fonts.check('900 1em \"Font Awesome 6 Free\"')"), 'Font Awesome loaded');
  expect(await page.eval("document.fonts.check('600 16px Inter')"), 'Inter loaded');
  await page.goto(base, '/results.html');
  eq(await page.eval("typeof Chart !== 'undefined' && Chart.version"), '4.5.1', 'pinned Chart.js version');
  await page.waitFor("[...document.querySelectorAll('canvas')].length === 3 && [...document.querySelectorAll('canvas')].every((c) => c.width > 0)");
});

test('figures agree: dashboard, gap analysis and mapping use the same data', async ({ page, base }) => {
  await page.goto(base, '/index.html');
  await page.waitFor("[...document.querySelectorAll('#statsGrid .stat-num')].map((x) => x.textContent).join() === '6,93,47,6'", 8000);
  // each domain badge on the dashboard equals the number of mapping rows for that domain
  const mismatched = await page.eval(`(() => {
    const M = window.GH_MAPPINGS, bad = [];
    document.querySelectorAll('a.kv-link[href^="mapping.html?d="]').forEach((a) => {
      const d = new URL(a.href, location.href).searchParams.get('d');
      const shown = parseInt(a.querySelector('.badge-pill').textContent, 10);
      const actual = M.filter((m) => m.domain === d).length;
      if (shown !== actual) bad.push(d + ': ' + shown + ' vs ' + actual);
    });
    return bad;
  })()`);
  eq(mismatched, [], 'dashboard badges vs mapping data');
  await page.goto(base, '/gaps.html');
  eq(await page.eval("[...document.querySelectorAll('#gapStats .stat-num')].map((x) => x.textContent)"), ['6', '93', '47', '13']);
  eq(await page.eval("document.querySelectorAll('.gap-row').length"), 13, 'gap list rows equal the "unique" figure');
  await page.goto(base, '/mapping.html');
  const totals = await page.eval("[cntStrong.textContent, cntModerate.textContent, cntPartial.textContent, document.querySelectorAll('#tableBody tr[data-i]').length]");
  eq(totals, ['21', '16', '10', 47], 'alignment counts computed from the data, and 47 rows');
});

test('wording: no page claims an official framework, "version 2024" or ISO 27001', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  for (const p of ALL_PAGES) {
    await page.goto(base, `/${p}.html`);
    const hit = await page.eval("(document.body.innerText.match(/version 2024|official Ghana|ISO 27001/i) || [null])[0]");
    eq(hit, null, `${p}: unwanted wording`);
  }
});

test('disclaimers: every page footer and both report versions say it is a self-assessment, not legal advice', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  for (const p of MAIN_PAGES) {
    await page.goto(base, `/${p}.html`);
    const t = await page.eval("(document.querySelector('.disclaimer') || {}).textContent || ''");
    expect(/not legal advice/.test(t) && /not an official publication/.test(t) && /stored only in this browser/.test(t), `${p}: footer disclaimer missing or incomplete`);
  }
  for (const p of ['results', 'results-print']) {
    await page.goto(base, `/${p}.html`);
    const t = await page.eval("(document.querySelector('.report-disclaimer') || {}).textContent || ''");
    expect(/not legal advice/.test(t) && /project-defined/.test(t), `${p}: report disclaimer missing`);
  }
});

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

test('figures agree: dashboard figures come from the requirements dataset', async ({ page, base }) => {
  await page.goto(base, '/index.html');
  await page.waitFor("[...document.querySelectorAll('#statsGrid .stat-num')].map((x) => x.textContent).join() === '53,93,153,6'", 8000);
  const groups = await page.eval(`(() => {
    const R = window.GHRequirements;
    const shown = [...document.querySelectorAll('#groupList a')].map((a) => [new URL(a.href, location.href).searchParams.get('g'), parseInt(a.querySelector('.badge-pill').textContent, 10)]);
    return { shown, expected: R.groups.map((g) => [g.id, R.requirements.filter((r) => r.group === g.id).length]) };
  })()`);
  eq(groups.shown, groups.expected, 'dashboard group badges equal the requirement counts');
  eq(await page.eval("[...document.querySelectorAll('#themeList .badge-pill')].map((b) => b.textContent)"), ['27 of 37 linked', '4 of 8 linked', '14 of 14 linked', '15 of 34 linked'], 'ISO theme link counts (60 of 93 controls are linked)');
  eq(await page.eval("document.querySelector('#groupList').textContent.includes('NCF')"), false, 'no retired NCF wording');
});

test('gaps: every figure and list is calculated from the requirements dataset', async ({ page, base }) => {
  const D = JSON.parse((await import('node:fs')).readFileSync(new URL('../../data/ghana-requirements.json', import.meta.url), 'utf8'));
  const linked = new Set(D.requirements.flatMap((r) => r.iso27002Links));
  const noLink = D.requirements.filter((r) => !r.iso27002Links.length);
  await page.goto(base, '/gaps.html');
  await page.waitFor("document.getElementById('gapReq').textContent !== '0'");
  eq(await page.eval("[...document.querySelectorAll('#gapStats .stat-num')].map((x) => x.textContent)"), [String(D.requirements.length), String(noLink.length), '93', String(93 - linked.size)], 'stat cards');
  eq(await page.eval("document.querySelectorAll('#noLinkList .gap-row').length"), noLink.length, 'requirements with no ISO link are listed');
  expect(await page.eval("/T2-21/.test(noLinkList.textContent)"), 'T2-21 (risk register) is the requirement with no ISO link');
  eq(await page.eval("document.querySelectorAll('#unrefList .gap-row').length"), 93 - linked.size, 'unreferenced ISO controls are listed');
  const t = await page.eval("document.body.innerText");
  expect(!/Based on proposed links/.test(t), 'no validation notice');
  expect(!/NCF/.test(t), 'no retired NCF wording');
  eq(await page.eval("document.querySelectorAll('#coverageBars .theme-bar').length"), 4, 'four themes shown');
});

test('wording: no page claims an official framework, "version 2024" or ISO 27001', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  for (const p of ALL_PAGES) {
    await page.goto(base, `/${p}.html`);
    const hit = await page.eval("(document.body.innerText.replace(/ISO 27001 Lead Auditor/g, '').match(/version 2024|official Ghana|ISO 27001/i) || [null])[0]");
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
    expect(/not legal advice/.test(t) && /plain-language summary/.test(t), `${p}: report disclaimer missing`);
  }
});

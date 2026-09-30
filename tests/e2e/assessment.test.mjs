import { test, expect, eq, sleep } from './harness.mjs';
import { SEED } from './fixtures.mjs';

const fillOrg = "orgName.value = 'Partial Test Org'; orgSector.value = 'Healthcare'; orgSize.value = 'Small (1-50)'; orgEmail.value = 'a@b.co';";

async function freshAssessment(page, base, width = 390) {
  await page.goto(base, '/index.html');
  await page.eval('localStorage.clear(); true');
  await page.goto(base, '/assessment.html', { width, height: 844 });
}

test('scoring: "partially implemented" counts as 2.5 (50%), not truncated to 2 (40%)', async ({ page, base }) => {
  await freshAssessment(page, base);
  await page.eval(`${fillOrg} goToStep(2); true`);
  await page.waitFor("getComputedStyle(step2).display === 'block'");
  await page.eval("document.querySelectorAll('#ncfControls input[type=radio][value=\"2.5\"]').forEach((r) => r.click()); goToStep(3); true");
  await page.waitFor("getComputedStyle(step3).display === 'block'");
  await page.eval("document.querySelectorAll('#isoControls input[type=radio][value=\"2.5\"]').forEach((r) => r.click()); true");
  await page.eval('submitAssessment(); true');
  await page.waitFor("location.pathname.endsWith('results.html') && document.getElementById('coverOverallScore') && document.getElementById('coverOverallScore').textContent === '50%'", 10000);
  const stored = await page.eval("(() => { const d = JSON.parse(localStorage.getItem('assessmentData')); const v = [...Object.values(d.ncf), ...Object.values(d.iso)]; return { n: v.length, distinct: [...new Set(v)] }; })()");
  eq(stored, { n: 24, distinct: [2.5] }, 'stored answers');
  eq(await page.eval("JSON.parse(localStorage.getItem('assessmentHistory')).length"), 1, 'history entry recorded');
  eq(await page.eval("localStorage.getItem('assessmentDraft')"), null, 'draft cleared after submit');
  await page.goto(base, '/index.html');
  eq(await page.eval("[statusPanel.querySelector('.ring-in b').textContent, ...[...statusPanel.querySelectorAll('.sp-bar b')].map((x) => x.textContent)]"), ['50%', '50%', '50%'], 'dashboard shows the same score as the report');
});

test('progress: answers autosave, restore on reload, and the dashboard offers to continue', async ({ page, base }) => {
  await freshAssessment(page, base);
  await page.eval(`${fillOrg} goToStep(2); true`);
  await page.waitFor("getComputedStyle(step2).display === 'block'");
  await page.eval("document.querySelectorAll('#ncfControls .opt input')[0].click(); document.querySelectorAll('#ncfControls .ctrl-item')[1].querySelector('.opt input').click(); true");
  await page.waitFor("(JSON.parse(localStorage.getItem('assessmentDraft') || 'null') || {}).answered === 2");
  const draft = await page.eval("(() => { const d = JSON.parse(localStorage.getItem('assessmentDraft')); return [d.answered, d.total, d.step, d.org.name]; })()");
  eq(draft, [2, 24, 2, 'Partial Test Org'], 'saved draft');

  await page.goto(base, '/assessment.html', { width: 390, height: 844 });
  await page.waitFor("document.querySelector('main [role=status]')");
  eq(await page.eval('[ncfProgress.textContent, orgName.value, getComputedStyle(step2).display]'), ['2', 'Partial Test Org', 'block'], 'restored');
  eq(await page.eval("document.querySelectorAll('#ncfControls .opt input:checked').length"), 2, 'radios restored');
  eq(await page.eval("[...document.querySelectorAll('.gs-trigger')].map((t) => t.textContent.trim())"), ['Healthcare', 'Small (1-50)'], 'custom dropdowns show the restored values');

  await page.goto(base, '/index.html');
  expect(await page.eval("/Unfinished assessment[^.]*2 of 24/.test(statusPanel.textContent)"), 'dashboard shows the unfinished assessment');
  await page.eval("document.querySelector('[data-discard]').click(); true");
  await page.waitFor("localStorage.getItem('assessmentDraft') === null && !document.querySelector('.sp-draft')");
});

test('validation: a missing sector shows the modal and marks the dropdown, which clears when chosen', async ({ page, base }) => {
  await freshAssessment(page, base);
  await page.eval("orgName.value = 'Accra Test Bank'; orgEmail.value = 'a@b.co'; goToStep(2); true");
  await page.waitFor("document.getElementById('appModalOverlay').classList.contains('open')");
  eq(await page.eval("orgSector.closest('.gs').querySelector('.gs-trigger').classList.contains('is-invalid')"), true, 'sector trigger marked invalid');
  await page.eval('closeModal(); true');
  await page.eval("orgSector.closest('.gs').querySelector('.gs-trigger').click(); true");
  await page.waitFor("document.querySelector('.gs-panel.is-open')");
  await page.eval("[...document.querySelectorAll('.gs-opt')].find((o) => o.textContent.includes('Healthcare')).click(); true");
  eq(await page.eval("[orgSector.value, orgSector.closest('.gs').querySelector('.gs-trigger').classList.contains('is-invalid')]"), ['Healthcare', false], 'value set, error cleared');
});

test('dashboard: trend, history and two-step "clear saved data"', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  await page.eval(`(() => {
    const mk = (v, days) => { const d = JSON.parse(JSON.stringify(${JSON.stringify(SEED)})); Object.keys(d.ncf).forEach((k) => d.ncf[k] = v); Object.keys(d.iso).forEach((k) => d.iso[k] = v); d.timestamp = new Date(Date.now() + days * 86400000).toISOString(); GHData.seedHistory(); GHData.addHistory(d); return d; };
    mk(5, 1); localStorage.setItem('assessmentData', JSON.stringify(mk(0, 2))); return true; })()`);
  await page.goto(base, '/index.html');
  eq(await page.eval("statusPanel.querySelector('.ring-in b').textContent"), '0%');
  eq(await page.eval("statusPanel.querySelector('.trend p').textContent"), 'Down 100 points since your previous assessment.');
  eq(await page.eval("statusPanel.querySelectorAll('.history li').length"), 3, 'history rows');
  const label = await page.eval("statusPanel.querySelector('.trend svg').getAttribute('aria-label')");
  expect(/^Score trend: \d+%, 100%, 0%$/.test(label), `sparkline has an accessible label with all three scores (got "${label}")`);
  await page.eval("document.querySelector('[data-clear-all]').click(); true");
  eq(await page.eval("[!!localStorage.getItem('assessmentData'), document.querySelector('[data-clear-all]').classList.contains('confirm')]"), [true, true], 'first click only arms it');
  await page.eval("document.querySelector('[data-clear-all]').click(); true");
  await page.waitFor("localStorage.getItem('assessmentData') === null && localStorage.getItem('assessmentHistory') === null");
});

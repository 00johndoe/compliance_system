import { test, expect, eq, sleep } from './harness.mjs';
import { SEED } from './fixtures.mjs';

const items = "document.querySelectorAll('#planList .plan-item').length";
const titles = "[...document.querySelectorAll('#planList .pi-title')].map((e) => e.textContent)";
const offsetDay = (n) => `(() => { const d = new Date(); d.setDate(d.getDate() + (${n})); return GHPlan.todayStr(d); })()`;

// Start from an empty plan (and optionally a stored assessment), then open the page.
async function open(page, base, { seed = false, width = 1280, height = 900, plan = [] } = {}) {
  if (seed) await page.seedAssessment(base, SEED); else { await page.goto(base, '/index.html'); await page.eval('localStorage.clear(); true'); }
  if (plan.length) {
    await page.goto(base, '/index.html');
    await page.eval(`(() => { const off = (n) => { const d = new Date(); d.setDate(d.getDate() + n); return GHPlan.todayStr(d); };
      ${JSON.stringify(plan)}.forEach((p) => { if (p.dueOffset !== undefined) p.due = off(p.dueOffset); GHPlan.add(p); }); return true; })()`);
  }
  await page.goto(base, '/actions.html', { width, height });
  await page.waitFor("document.getElementById('planList') !== null");
}

test('plan: suggestions come from the latest assessment, can be added, and are never duplicated', async ({ page, base }) => {
  await open(page, base, { seed: true });
  // SEED has 6 areas below 75% (Legal 50, Incident 25, Capacity 25, Organizational 50, Physical 50, Technological 50); Governance is exactly 75
  eq(await page.eval("document.querySelectorAll('#sgList .sg-item').length"), 6, 'suggested areas');
  eq(await page.eval(items), 0, 'nothing in the plan yet');
  await page.eval("document.querySelector('[data-add-suggest]').click(); true");
  await page.waitFor(`${items} === 1`);
  eq(await page.eval("document.querySelectorAll('#sgList .sg-item').length"), 5, 'added suggestion leaves the list');
  const first = await page.eval("(() => { const i = GHPlan.list()[0]; return { kind: i.source.kind, status: i.status, priority: i.priority, pct: i.source.pct }; })()");
  eq(first.kind, 'gap'); eq(first.status, 'todo');
  // same bands as the report: below 25% immediate, below 50% high, below 75% medium
  expect(first.priority === 'high' && first.pct === 25, `weakest area (25%) is added first with "high" priority (got ${first.priority}, ${first.pct}%)`);
  eq(await page.eval("['immediate', 'high', 'medium', 'low'].map((p, i) => GHPlan.priorityForScore([10, 25, 50, 75][i]))"), ['immediate', 'high', 'medium', 'low'], 'priority bands');
  await page.eval("document.getElementById('addAllBtn').click(); true");
  await page.waitFor(`${items} === 6`);
  eq(await page.eval("document.getElementById('suggest').hidden"), true, 'no suggestions left');
  eq(await page.eval("(() => { const s = GHPlan.suggestionFor('Incident Response', 'Ghana NCF', 25); const r = GHPlan.add(s); return [r.existing === true, GHPlan.list().length]; })()"), [true, 6], 'adding the same gap again returns the existing action');
});

test('plan: add, edit, change status, and delete with undo', async ({ page, base }) => {
  await open(page, base);
  eq(await page.eval("document.getElementById('emptyState').hidden"), false, 'empty state shown');
  await page.eval("document.getElementById('addBtn').click(); true");
  await page.waitFor("document.getElementById('modalOverlay').classList.contains('open')");
  await page.eval(`(() => { fTitle.value = 'Write an incident response procedure'; fNotes.value = 'Cover the 24-hour reporting rule'; fOwner.value = 'A. Mensah'; fPriority.value = 'high'; fDue.value = ${offsetDay('10')}; modalSave.click(); return true; })()`);
  await page.waitFor(`${items} === 1`);
  eq(await page.eval("document.getElementById('modalOverlay').classList.contains('open')"), false, 'dialog closes on save');
  const card = await page.eval("(() => { const c = document.querySelector('.plan-item'); return { title: c.querySelector('.pi-title').textContent, pri: c.dataset.priority, status: c.dataset.status, owner: /A\\. Mensah/.test(c.textContent), notes: /24-hour/.test(c.textContent) }; })()");
  eq(card, { title: 'Write an incident response procedure', pri: 'high', status: 'todo', owner: true, notes: true });

  await page.eval("document.querySelector('[data-edit]').click(); true");
  await page.waitFor("document.getElementById('modalOverlay').classList.contains('open') && fTitle.value.startsWith('Write')");
  eq(await page.eval('[fPriority.value, fOwner.value]'), ['high', 'A. Mensah'], 'edit form is pre-filled');
  await page.eval("fTitle.value = 'Approve the incident response procedure'; modalSave.click(); true");
  await page.waitFor("document.querySelector('.pi-title').textContent === 'Approve the incident response procedure'");

  await page.eval("document.querySelector('[data-set-status=\"doing\"]').click(); true");
  await page.waitFor("document.querySelector('.plan-item').dataset.status === 'doing'");
  await page.eval("document.querySelector('[data-toggle]').click(); true");
  await page.waitFor("document.querySelector('.plan-item').dataset.status === 'done'");
  eq(await page.eval("GHPlan.list()[0].completedAt !== ''"), true, 'completion time recorded');
  await page.eval("document.querySelector('[data-toggle]').click(); true");
  await page.waitFor("document.querySelector('.plan-item').dataset.status === 'todo'");
  eq(await page.eval("GHPlan.list()[0].completedAt"), '', 'completion time cleared when reopened');

  await page.eval("document.querySelector('[data-delete]').click(); true");
  await page.waitFor(`${items} === 0`);
  await page.waitFor("document.getElementById('toast').classList.contains('show') && !document.getElementById('toastUndo').hidden");
  await page.eval("document.getElementById('toastUndo').click(); true");
  await page.waitFor(`${items} === 1`);
  eq(await page.eval("GHPlan.list().length"), 1, 'undo restores the action');
});

test('plan: the form validates, and the data layer clamps oversized or invalid values', async ({ page, base }) => {
  await open(page, base);
  await page.eval("document.getElementById('addBtn').click(); true");
  await page.waitFor("document.getElementById('modalOverlay').classList.contains('open')");
  await page.eval("fTitle.value = '   '; modalSave.click(); true");
  await page.waitFor("!document.getElementById('fTitleErr').hidden");
  eq(await page.eval("[document.getElementById('modalOverlay').classList.contains('open'), fTitle.getAttribute('aria-invalid'), GHPlan.list().length]"), [true, 'true', 0], 'blank title is rejected and the dialog stays open');
  eq(await page.eval("document.activeElement.id"), 'fTitle', 'focus returns to the field with the error');
  eq(await page.eval("(() => { const i = GHPlan.add({ title: 'Two\\r\\nlines', owner: 'A\\nB', notes: 'keep\\nbreaks' }).item; return [i.title, i.owner, i.notes]; })()"), ['Two lines', 'A B', 'keep\nbreaks'], 'single-line fields are flattened; notes keep their line breaks');
  eq(await page.eval("(() => { const r = GHPlan.add({ title: 'x'.repeat(500), notes: 'n'.repeat(5000), owner: 'o'.repeat(500), status: 'bogus', priority: 'urgent', due: '2026-02-31' }); const i = r.item; return [i.title.length, i.notes.length, i.owner.length, i.status, i.priority, i.due]; })()"), [140, 1000, 80, 'todo', 'medium', ''], 'lengths clamped, unknown enums defaulted, impossible date dropped');
});

test('plan: due dates drive overdue and due-soon markers, counts and the Overdue filter', async ({ page, base }) => {
  await open(page, base, { plan: [
    { title: 'Overdue item', dueOffset: -3, priority: 'high' },
    { title: 'Due today item', dueOffset: 0 },
    { title: 'Due soon item', dueOffset: 2 },
    { title: 'Later item', dueOffset: 20 },
    { title: 'Finished late item', dueOffset: -5, status: 'done' },
  ] });
  const chips = await page.eval("[...document.querySelectorAll('.plan-item')].map((c) => [c.querySelector('.pi-title').textContent, (c.querySelector('.chip.overdue, .chip.soon') || {}).textContent || ''])");
  const byTitle = Object.fromEntries(chips);
  expect(/Overdue by 3 days/.test(byTitle['Overdue item']), `overdue chip (${byTitle['Overdue item']})`);
  expect(/Due today/.test(byTitle['Due today item']), 'due today chip');
  expect(/Due in 2 days/.test(byTitle['Due soon item']), 'due soon chip');
  eq(byTitle['Later item'], '', 'a date far ahead has no warning');
  eq(byTitle['Finished late item'], '', 'a completed item is never overdue');
  eq(await page.eval("[cntOverdue.textContent, cntTodo.textContent, cntDone.textContent]"), ['1', '4', '1']);
  await page.eval("document.querySelector('#chips [data-filter=\"overdue\"]').click(); true");
  await page.waitFor(`${items} === 1`);
  eq(await page.eval(titles), ['Overdue item']);
});

test('plan: filters and sorting', async ({ page, base }) => {
  await open(page, base, { plan: [
    { title: 'C low, no date', priority: 'low' },
    { title: 'A immediate, later', priority: 'immediate', dueOffset: 30 },
    { title: 'B medium, soonest', priority: 'medium', dueOffset: 1 },
    { title: 'D high, done', priority: 'high', dueOffset: 2, status: 'done' },
    { title: 'E doing', priority: 'high', status: 'doing', dueOffset: 5 },
  ] });
  eq(await page.eval(titles), ['B medium, soonest', 'E doing', 'A immediate, later', 'C low, no date', 'D high, done'], 'default: soonest due first, undated then completed last');
  await page.eval("(() => { const s = document.getElementById('sortSelect'); s.value = 'priority'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()");
  await page.waitFor("document.querySelector('.pi-title').textContent === 'A immediate, later'");
  eq((await page.eval(titles)).slice(0, 3), ['A immediate, later', 'E doing', 'B medium, soonest']);
  await page.eval("(() => { const s = document.getElementById('sortSelect'); s.value = 'title'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()");
  await page.waitFor("document.querySelector('.pi-title').textContent.startsWith('A ')");
  await page.eval("document.querySelector('#chips [data-filter=\"doing\"]').click(); true");
  await page.waitFor(`${items} === 1`);
  eq(await page.eval(titles), ['E doing']);
  eq(await page.eval("[...document.querySelectorAll('#chips .filter-btn')].map((b) => b.textContent)"), ['All (5)', 'To do (3)', 'In progress (1)', 'Done (1)', 'Overdue (0)']);
  await page.eval("document.querySelector('#chips [data-filter=\"done\"]').click(); true");
  await page.waitFor("document.querySelector('.pi-title').textContent === 'D high, done'");
  await page.eval("document.getElementById('clearDoneBtn').click(); true");
  eq(await page.eval("GHPlan.list().length"), 5, 'clearing completed needs a second click');
  await page.eval("document.getElementById('clearDoneBtn').click(); true");
  await page.waitFor("GHPlan.list().length === 4");
});

test('plan: export and import round-trip; hostile or corrupted data is sanitised and never rendered as HTML', async ({ page, base }) => {
  await open(page, base, { plan: [
    { title: 'Keep me', notes: 'line one\nline two', owner: 'Ama', priority: 'high', dueOffset: 4 },
    { title: '=HYPERLINK("http://x")', status: 'doing' },
  ] });
  const json = await page.eval('GHPlan.exportJSON()');
  const csv = await page.eval('GHPlan.exportCSV()');
  expect(csv.charCodeAt(0) === 0xFEFF && csv.includes("\"'=HYPERLINK"), 'CSV has a BOM and neutralises formulas');
  await page.eval('GHPlan.clearAll(); true');
  eq(await page.eval(`JSON.stringify(GHPlan.importJSON(${JSON.stringify(json)}, 'merge'))`), '{"ok":true,"added":2,"updated":0,"skipped":0,"total":2}', 'round trip');
  eq(await page.eval(`JSON.stringify(GHPlan.importJSON(${JSON.stringify(json)}, 'merge'))`), '{"ok":true,"added":0,"updated":0,"skipped":2,"total":2}', 'importing the same file again changes nothing');

  const bad = {
    'not JSON': 'this is not json',
    'wrong file type': JSON.stringify({ type: 'something-else', items: [] }),
    'no items array': JSON.stringify({ type: 'action-plan' }),
    'empty': '   ',
  };
  for (const [name, text] of Object.entries(bad)) {
    eq(await page.eval(`GHPlan.importJSON(${JSON.stringify(text)}).ok`), false, `rejects: ${name}`);
  }
  eq(await page.eval("GHPlan.importJSON('x'.repeat(1000001)).ok"), false, 'rejects an oversized file');

  const hostile = { type: 'action-plan', items: [
    { title: '<img src=x onerror="window.__pwned=1">', notes: '<script>window.__pwned=2</script>', owner: '"><svg onload=window.__pwned=3>', status: 'evil', priority: 'evil', due: 'tomorrow' },
    { title: 'x', id: '../../etc/passwd' },
    { title: '', notes: 'no title' },
    'a string', null, 42,
  ] };
  const res = await page.eval(`GHPlan.importJSON(${JSON.stringify(JSON.stringify(hostile))}, 'replace')`);
  eq([res.ok, res.added, res.skipped], [true, 2, 4], 'usable items kept; junk skipped');
  eq(await page.eval("GHPlan.list().map((i) => [i.status, i.priority, i.due, /^[A-Za-z0-9_-]+$/.test(i.id)])"), [['todo', 'medium', '', true], ['todo', 'medium', '', true]], 'enums defaulted, date dropped, ids sanitised');
  await page.goto(base, '/actions.html');
  await page.waitFor(`${items} === 2`);
  eq(await page.eval("[document.querySelectorAll('#planList img, #planList svg, #planList script').length, typeof window.__pwned]"), [0, 'undefined'], 'nothing was injected into the page');
  expect(await page.eval("document.querySelector('.pi-title').textContent.includes('<img src=x')"), 'the text is shown literally');

  // corrupted storage must not break the page
  await page.eval("localStorage.setItem('actionPlan', '{{{ not json'); true");
  page.problems.length = 0;
  await page.goto(base, '/actions.html');
  eq([await page.eval(items), page.problems], [0, []], 'corrupted storage behaves like an empty plan, without errors');
});

test('plan: the dashboard shows progress, overdue work, and a prompt to build the plan', async ({ page, base }) => {
  await page.goto(base, '/index.html');
  await page.eval('localStorage.clear(); true');
  await page.goto(base, '/index.html');
  eq(await page.eval("document.getElementById('planCard').hidden"), true, 'hidden with no assessment and no plan');
  await page.seedAssessment(base, SEED);
  await page.goto(base, '/index.html');
  expect(await page.eval("/6 areas in your latest assessment/.test(planCard.textContent) && !!planCard.querySelector('a[href=\"actions.html\"]')"), 'prompts to build a plan from the gaps');
  await page.eval(`(() => { const off = (n) => { const d = new Date(); d.setDate(d.getDate() + n); return GHPlan.todayStr(d); };
    GHPlan.add({ title: 'Late', due: off(-2) }); GHPlan.add({ title: 'Next', due: off(1) }); GHPlan.add({ title: 'Done one', status: 'done' }); return true; })()`);
  await page.goto(base, '/index.html');
  const card = await page.eval("({ text: planCard.textContent.replace(/\\s+/g, ' '), bar: planCard.querySelector('[role=progressbar]').getAttribute('aria-valuenow') })");
  expect(/1 of 3 actions done \(33%\)/.test(card.text), `progress text (${card.text})`);
  expect(/1 action overdue/.test(card.text) && /Next due: Late/.test(card.text), 'overdue and next-due shown');
  eq(card.bar, '33', 'progressbar value');
});

test('report: each recommendation can be added to the action plan, once', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  await page.goto(base, '/results.html');
  await page.waitFor("document.querySelectorAll('#recommendations .plan-add').length === 10");
  await page.eval("document.querySelector('#recommendations .plan-add').click(); true");
  await page.waitFor("GHPlan.list().length === 1 && document.querySelector('#recommendations .plan-add').classList.contains('is-added')");
  const added = await page.eval("(() => { const i = GHPlan.list()[0]; return [i.source.kind, i.source.pct, i.status]; })()");
  eq(added[0], 'gap'); expect(added[1] <= 25, 'the weakest area is listed first, so it is added first');
  await page.eval("document.querySelector('#recommendations .plan-add').click(); true");
  await page.waitFor("location.pathname.endsWith('actions.html')");
  await page.waitFor(`${items} === 1`);
  eq(await page.eval("document.querySelectorAll('#sgList .sg-item').length"), 5, 'that area is no longer suggested');
});

test('plan: dialog traps focus, closes on Escape and returns focus; layout holds with very long text at 320px', async ({ page, base }) => {
  const long = 'Unbroken' + 'x'.repeat(120);
  await open(page, base, { width: 320, height: 640, plan: [{ title: long, notes: 'n'.repeat(400) + ' ' + 'y'.repeat(150), owner: 'O'.repeat(70), priority: 'immediate', dueOffset: -1 }] });
  eq(await page.eval('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, 'no sideways scroll with long unbroken text');
  await page.eval("document.getElementById('addBtn').focus(); document.getElementById('addBtn').click(); true");
  await page.waitFor("document.getElementById('modalOverlay').classList.contains('open')");
  eq(await page.eval("document.body.classList.contains('modal-open')"), true, 'page scroll locked behind the dialog');
  await page.eval("document.getElementById('modalSave').focus(); true");
  await page.key('Tab', 'Tab', 9);
  expect(await page.eval("document.getElementById('modal').contains(document.activeElement)"), 'Tab stays inside the dialog');
  await page.key('Escape', 'Escape', 27);
  await page.waitFor("!document.getElementById('modalOverlay').classList.contains('open')");
  eq(await page.eval("document.activeElement.id"), 'addBtn', 'focus returns to the button that opened it');
  eq(await page.eval('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, 'still no sideways scroll');
});

test('calendar: the .ics file has stable, correctly escaped all-day events with reminders, and cannot be injected into', async ({ page, base }) => {
  await open(page, base, { plan: [
    { title: 'Approve policy, then publish; review', notes: 'Line one\nLine two, with comma; semicolon and \\ backslash', owner: 'Ama', priority: 'high', due: '2026-12-31' },
    { title: 'Leap day task', due: '2028-02-28' },
    { title: 'Café Ünïcode ✓ ' + 'long '.repeat(30), due: '2027-03-01', priority: 'low' },
    { title: 'Already done', due: '2026-11-01', status: 'done' },
    { title: 'No due date' },
    { title: 'Evil\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:injected', notes: 'x\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:also injected', due: '2026-10-05' },
  ] });
  const r = await page.eval(`(() => {
    const a = GHPlan.exportICS(), b = GHPlan.exportICS(), enc = new TextEncoder();
    const lines = a.ics.split('\\r\\n');
    return { ics: a.ics, count: a.count, noDue: a.noDue, lines: lines.length, maxBytes: Math.max(...lines.map((l) => enc.encode(l).length)),
      bareBreaks: /[^\\r]\\n|\\r[^\\n]/.test(a.ics), uidsA: a.ics.match(/^UID:.*$/gm), uidsB: b.ics.match(/^UID:.*$/gm) };
  })()`);
  eq([r.count, r.noDue], [4, 1], 'open dated actions exported; the done and the undated one are not');
  expect(r.ics.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\n') && r.ics.endsWith('END:VCALENDAR\r\n'), 'calendar envelope, CRLF line endings');
  eq(r.bareBreaks, false, 'every line break is CRLF');
  expect(r.maxBytes <= 75, `no line longer than 75 octets (longest: ${r.maxBytes})`);
  const unfolded = r.ics.replace(/\r\n /g, '');
  eq((unfolded.match(/^BEGIN:VEVENT$/gm) || []).length, 4, 'exactly four events, none injected');
  expect(unfolded.includes('SUMMARY:Due: Approve policy\\, then publish\\; review'), 'commas and semicolons escaped in SUMMARY');
  expect(unfolded.includes('Line one\\nLine two\\, with comma\\; semicolon and \\\\ backslash'), 'notes: newline, comma, semicolon and backslash escaped');
  expect(unfolded.includes('DTSTART;VALUE=DATE:20261231') && unfolded.includes('DTEND;VALUE=DATE:20270101'), 'a due date at year end ends on 1 January (all-day, exclusive end)');
  expect(unfolded.includes('DTSTART;VALUE=DATE:20280228') && unfolded.includes('DTEND;VALUE=DATE:20280229'), 'leap day handled');
  expect(unfolded.includes('Café Ünïcode ✓ long'), 'accented and symbol characters survive line folding intact');
  expect(!/^SUMMARY:injected/m.test(unfolded) && !/^SUMMARY:also injected/m.test(unfolded), 'line breaks in titles or notes cannot start new properties');
  eq((unfolded.match(/^BEGIN:VALARM$/gm) || []).length, 8, 'two reminders per event');
  expect(/TRIGGER:-PT15H/.test(unfolded) && /TRIGGER:PT9H/.test(unfolded), '9am the day before and 9am on the day');
  expect(/PRIORITY:3/.test(unfolded) && /PRIORITY:7/.test(unfolded) && /PRIORITY:5/.test(unfolded), 'priority mapped to iCalendar values');
  eq(r.uidsA, r.uidsB, 'event IDs are stable between exports, so re-importing updates instead of duplicating');
  eq(new Set(r.uidsA).size, 4, 'one unique ID per action');
  expect(r.uidsA.every((u) => /^UID:[A-Za-z0-9_-]+@gh-cybercomply$/.test(u)), 'well-formed IDs');
});

test('calendar: the button downloads a .ics file and is disabled when no open action has a due date', async ({ page, base }) => {
  await open(page, base, { plan: [{ title: 'Undated' }, { title: 'Finished', due: '2026-11-01', status: 'done' }] });
  eq(await page.eval('document.getElementById("icsBtn").disabled'), true, 'nothing to add yet');
  await page.eval("GHPlan.add({ title: 'Dated one', due: '2027-01-15' }); GHPlan.add({ title: 'Dated two', due: '2027-01-20' }); true");
  await page.goto(base, '/actions.html');
  await page.waitFor("document.getElementById('icsBtn').disabled === false");
  await page.eval(`window.__dl = null; const O = window.Blob; window.Blob = function (p, o) { window.__blob = { type: o && o.type, text: p.join('') }; return new O(p, o); };
    HTMLAnchorElement.prototype.click = function () { window.__dl = { name: this.download }; }; true`);
  await page.eval("document.getElementById('icsBtn').click(); true");
  await page.waitFor('!!window.__dl');
  const got = await page.eval('({ name: window.__dl.name, type: window.__blob.type, hasCal: window.__blob.text.startsWith("BEGIN:VCALENDAR"), toast: document.getElementById("toastText").textContent })');
  expect(/^action-plan-deadlines-\d{4}-\d{2}-\d{2}\.ics$/.test(got.name), `file name (${got.name})`);
  eq(got.type, 'text/calendar;charset=utf-8', 'calendar media type');
  expect(got.hasCal, 'file content is a calendar');
  expect(/2 deadlines/.test(got.toast) && /1 action without a due date skipped/.test(got.toast), `toast explains what was exported (${got.toast})`);
});

test('navigation: "Action Plan" is in the desktop menu and the mobile menu of every page, active on its own page', async ({ page, base }) => {
  for (const p of ['index', 'mapping', 'assessment', 'gaps', 'actions']) {
    await page.goto(base, `/${p}.html`, { width: 1280 });
    const desk = await page.eval("(() => { const a = [...document.querySelectorAll('#desktopNav a')].find((x) => x.textContent.trim() === 'Action Plan'); return a ? [a.getAttribute('href'), a.getAttribute('aria-current')] : null; })()");
    eq(desk && desk[0], 'actions.html', `${p}: desktop link`);
    eq(desk[1], p === 'actions' ? 'page' : null, `${p}: active state`);
    expect(await page.eval("[...document.querySelectorAll('#drawer a')].some((x) => x.textContent.trim() === 'Action Plan')"), `${p}: drawer link`);
  }
  await page.seedAssessment(base, SEED);
  await page.goto(base, '/results.html', { width: 390, height: 844 });
  expect(await page.eval("[...document.querySelectorAll('#drawer nav[aria-label=\"Site pages\"] a')].some((x) => x.textContent.trim() === 'Action Plan')"), 'results: drawer link');
  await page.goto(base, '/index.html', { width: 1024, height: 800 });
  eq(await page.eval('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, 'six desktop links still fit at 1024px');
});

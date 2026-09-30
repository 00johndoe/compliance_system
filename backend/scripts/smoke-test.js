'use strict';

const DATA = require('../../data/ghana-requirements.json');
const LINKS = DATA.requirements.reduce((n, r) => n + r.iso27002Links.length, 0);

/**
 * End-to-end smoke test against a running server.
 * Usage: BASE=http://localhost:8000 node scripts/smoke-test.js
 * Exits non-zero on the first failed assertion.
 */

const BASE = process.env.BASE || 'http://localhost:8000';

let passed = 0;
let failed = 0;

function ok(cond, label) {
  if (cond) {
    passed += 1;
    console.log(`  ✓ ${label}`);
  } else {
    failed += 1;
    console.error(`  ✗ ${label}`);
  }
}

async function get(path) {
  const r = await fetch(`${BASE}${path}`);
  return { status: r.status, body: await r.json().catch(() => null) };
}

async function post(path, data) {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}

async function run() {
  console.log(`\nSmoke test against ${BASE}\n`);

  const health = await get('/api/health');
  ok(health.status === 200 && health.body.status === 'ok', 'GET /api/health');
  ok(health.body.db === 'connected', 'database connected');

  const ghana = await get('/api/frameworks/ghana');
  const ghanaControls = (ghana.body.domains || []).reduce((n, d) => n + d.controls.length, 0);
  ok(ghana.status === 200 && ghanaControls === DATA.requirements.length, `GET /api/frameworks/ghana (${DATA.requirements.length} requirements, got ${ghanaControls})`);
  ok((ghana.body.domains || []).length === DATA.groups.length, `ghana requirements in ${DATA.groups.length} groups`);
  ok((ghana.body.domains || []).every((d) => d.controls.every((c) => c.tier && c.source)), 'every Ghana requirement carries a tier and a source citation');

  const iso = await get('/api/frameworks/iso27002');
  const isoControls = (iso.body.themes || []).reduce((n, t) => n + t.controls.length, 0);
  ok(iso.status === 200 && isoControls === 93, `GET /api/frameworks/iso27002 (93 controls, got ${isoControls})`);

  const mapping = await get('/api/mapping');
  ok(mapping.status === 200 && Array.isArray(mapping.body) && mapping.body.length === LINKS, `GET /api/mapping (${LINKS} proposed links, got ${mapping.body && mapping.body.length})`);
  ok(mapping.body.every((m) => m.requirement && m.iso && m.status === 'proposed' && !('alignment' in m)), 'mapping rows are unrated proposals');

  const gaps = await get('/api/gaps');
  ok(gaps.status === 200 && Array.isArray(gaps.body.ghana_unique) && Array.isArray(gaps.body.iso_unique) && Array.isArray(gaps.body.coverage), 'GET /api/gaps');
  const linkedIso = new Set(DATA.requirements.flatMap((r) => r.iso27002Links));
  ok(gaps.body.iso_unique.length === 93 - linkedIso.size, `gaps: ISO controls not linked = ${93 - linkedIso.size} (got ${gaps.body.iso_unique.length})`);
  ok(gaps.body.ghana_unique.every((g) => DATA.requirements.find((r) => r.id === g.control).iso27002Links.length === 0), 'gaps: Ghana-only items have no ISO link');

  // Create an assessment. Only Tier 1A applies by default, so T1B/T2 answers are ignored.
  const validPayload = {
    organization: { name: 'Smoke Test Ltd', sector: 'Financial Services', size: 'Medium (51-250)', email: 'ops@smoke.test' },
    ghana_responses: { 'T1A-01': 5, 'T1A-02': 3, 'T1B-11': 5, 'T2-04': 5 },
    iso_responses: { '5.1': 5, '8.5': 4, '8.7': 2 },
  };
  const created = await post('/api/assess', validPayload);
  ok(created.status === 201 && !!created.body.id, `POST /api/assess -> ${created.body && created.body.id}`);
  ok(typeof created.body.ghana_scores.overall === 'number', 'assessment has ghana overall score');
  ok(Array.isArray(created.body.recommendations) && created.body.recommendations.length > 0, 'assessment has recommendations');
  ok(['Optimized', 'Managed', 'Defined', 'Developing', 'Initial', 'Non-Existent'].includes(created.body.ghana_maturity), `ghana maturity label: ${created.body.ghana_maturity}`);

  const id = created.body.id;

  const countCtl = (r) => r.body.ghana_scores.domains.reduce((n, d) => n + d.controls.length, 0);
  ok(countCtl(created) === 2, `default applicability scores only Tier 1A (2 requirements, got ${countCtl(created)})`);
  ok(created.body.ghana_scores.overall === 80, `Tier 1A score ignores non-applicable answers (80, got ${created.body.ghana_scores.overall})`);
  const withData = await post('/api/assess', { ...validPayload, applicability: { personalData: true } });
  ok(withData.status === 201 && countCtl(withData) === 20, `personal-data processor scores 1A + 1B (20, got ${withData.body.ghana_scores && countCtl(withData)})`);
  const allTiers = await post('/api/assess', { ...validPayload, applicability: { personalData: true, ciiOwner: true } });
  ok(allTiers.status === 201 && countCtl(allTiers) === DATA.requirements.length, `CII owner scores all tiers (${DATA.requirements.length})`);
  ok(allTiers.body.applicability.ciiOwner === true && created.body.applicability.ciiOwner === false, 'applicability is stored with the assessment');
  for (const a of [withData, allTiers]) await fetch(`${BASE}/api/assessments/${a.body.id}`, { method: 'DELETE' });
  const badApplicability = await post('/api/assess', { ...validPayload, applicability: { ciiOwner: 'yes' } });
  ok(badApplicability.status === 400, 'reject non-boolean applicability -> 400');

  const fetched = await get(`/api/assessments/${id}`);
  ok(fetched.status === 200 && fetched.body.id === id, 'GET /api/assessments/:id');

  const list = await get('/api/assessments');
  ok(list.status === 200 && list.body.some((a) => a.id === id), 'GET /api/assessments (contains new id)');

  const report = await post('/api/report', { assessment_id: id });
  ok(report.status === 200 && report.body.id === id, 'POST /api/report');

  const missing = await get('/api/assessments/deadbeef');
  ok(missing.status === 404, 'GET unknown assessment -> 404');

  const del = await fetch(`${BASE}/api/assessments/${id}`, { method: 'DELETE' });
  ok(del.status === 200, 'DELETE /api/assessments/:id');

  // ─── Input validation (should be rejected with 400) ───
  const badEmail = await post('/api/assess', { ...validPayload, organization: { ...validPayload.organization, email: 'not-an-email' } });
  ok(badEmail.status === 400, 'reject invalid email -> 400');

  const badSector = await post('/api/assess', { ...validPayload, organization: { ...validPayload.organization, sector: 'Banking' } });
  ok(badSector.status === 400, 'reject unknown sector -> 400');

  const missingName = await post('/api/assess', { ...validPayload, organization: { ...validPayload.organization, name: '' } });
  ok(missingName.status === 400, 'reject empty name -> 400');

  const outOfRange = await post('/api/assess', { ...validPayload, ghana_responses: { 'T1A-01': 9 } });
  ok(outOfRange.status === 400, 'reject maturity out of range (9) -> 400');

  const badType = await post('/api/assess', { ...validPayload, iso_responses: { '5.1': 'high' } });
  ok(badType.status === 400, 'reject non-numeric maturity -> 400');

  const unknownControl = await post('/api/assess', { ...validPayload, ghana_responses: { 'GOV-01': 3 } });
  ok(unknownControl.status === 400, 'reject retired NCF control id (GOV-01) -> 400');

  const badReport = await post('/api/report', { assessment_id: '' });
  ok(badReport.status === 400, 'reject empty assessment_id -> 400');

  // ── Front-end security: CSP, self-hosted assets, and no repository exposure ──
  const page = await fetch(`${BASE}/index.html`);
  const csp = page.headers.get('content-security-policy') || '';
  ok(page.status === 200, 'GET /index.html');
  ok(csp.includes("default-src 'self'") && csp.includes("object-src 'none'") && csp.includes("frame-ancestors 'none'"), 'Content-Security-Policy is set');
  ok(!/unsafe-eval/.test(csp), "CSP does not allow 'unsafe-eval'");
  ok(!/https?:\/\//.test(csp), 'CSP allows no third-party origins');
  ok(page.headers.get('x-content-type-options') === 'nosniff', 'X-Content-Type-Options: nosniff');
  const indexHtml = await page.text();
  ok(!/(cdn\.|cdnjs|googleapis|gstatic|unpkg)/i.test(indexHtml), 'index.html references no CDN assets');
  for (const p of ['/backend/server.js', '/backend/package.json', '/backend/src/data/frameworks.js', '/server.py', '/docs/ghana-obligations-draft.md', '/.env']) {
    const r = await fetch(`${BASE}${p}`);
    ok(r.status === 404, `not publicly served: ${p} (got ${r.status})`);
  }
  for (const p of ['/vendor/chart.umd.min.js', '/vendor/fontawesome/css/all.min.css', '/mobile.js', '/mapping', '/actions', '/gh-plan.js', '/gh-requirements.js', '/favicon.ico']) {
    const r = await fetch(`${BASE}${p}`);
    ok(r.status === 200, `served: ${p} (got ${r.status})`);
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
}

run().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});

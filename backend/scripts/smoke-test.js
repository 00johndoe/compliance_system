'use strict';

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
  ok(ghana.status === 200 && ghanaControls === 37, `GET /api/frameworks/ghana (37 controls, got ${ghanaControls})`);

  const iso = await get('/api/frameworks/iso27002');
  const isoControls = (iso.body.themes || []).reduce((n, t) => n + t.controls.length, 0);
  ok(iso.status === 200 && isoControls === 93, `GET /api/frameworks/iso27002 (93 controls, got ${isoControls})`);

  const mapping = await get('/api/mapping');
  ok(mapping.status === 200 && Array.isArray(mapping.body) && mapping.body.length === 47, `GET /api/mapping (47 rows, got ${mapping.body && mapping.body.length})`);

  const gaps = await get('/api/gaps');
  ok(gaps.status === 200 && Array.isArray(gaps.body.ghana_unique), 'GET /api/gaps');

  // Create an assessment. GOV-01 fully mature (5), everything else default 0.
  const validPayload = {
    organization: { name: 'Smoke Test Ltd', sector: 'Financial Services', size: 'Medium (51-250)', email: 'ops@smoke.test' },
    ghana_responses: { 'GOV-01': 5, 'GOV-03': 4, 'PROT-01': 3 },
    iso_responses: { '5.1': 5, '8.5': 4, '8.7': 2 },
  };
  const created = await post('/api/assess', validPayload);
  ok(created.status === 201 && !!created.body.id, `POST /api/assess -> ${created.body && created.body.id}`);
  ok(typeof created.body.ghana_scores.overall === 'number', 'assessment has ghana overall score');
  ok(Array.isArray(created.body.recommendations) && created.body.recommendations.length > 0, 'assessment has recommendations');
  ok(['Optimized', 'Managed', 'Defined', 'Developing', 'Initial', 'Non-Existent'].includes(created.body.ghana_maturity), `ghana maturity label: ${created.body.ghana_maturity}`);

  const id = created.body.id;

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

  const outOfRange = await post('/api/assess', { ...validPayload, ghana_responses: { 'GOV-01': 9 } });
  ok(outOfRange.status === 400, 'reject maturity out of range (9) -> 400');

  const badType = await post('/api/assess', { ...validPayload, iso_responses: { '5.1': 'high' } });
  ok(badType.status === 400, 'reject non-numeric maturity -> 400');

  const unknownControl = await post('/api/assess', { ...validPayload, ghana_responses: { 'GOV-99': 3 } });
  ok(unknownControl.status === 400, 'reject unknown control id -> 400');

  const badReport = await post('/api/report', { assessment_id: '' });
  ok(badReport.status === 400, 'reject empty assessment_id -> 400');

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
}

run().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});

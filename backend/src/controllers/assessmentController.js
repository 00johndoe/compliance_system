'use strict';

const Assessment = require('../models/Assessment');
const asyncHandler = require('../middleware/asyncHandler');
const { getFramework } = require('../services/frameworkRepo');
const {
  calculateScores,
  getMaturityLabel,
  generateRecommendations,
  round1,
} = require('../services/scoring');

/**
 * Accept the responses map under several possible keys so the endpoint works
 * with both the canonical contract (ghana_responses / iso_responses) and
 * shorter aliases (ghana / iso / ncf).
 */
function pickResponses(body, keys) {
  for (const k of keys) {
    if (body && typeof body[k] === 'object' && body[k] !== null) return body[k];
  }
  return {};
}

/** Convert a { controlId: maturity } map into [{ id, maturity }] for storage. */
function responsesToArray(obj) {
  return Object.entries(obj || {}).map(([id, maturity]) => ({
    id,
    maturity: Number(maturity) || 0,
  }));
}

/** Coerce arbitrary organization input into the known shape. */
function normalizeOrg(org) {
  if (!org || typeof org !== 'object') return {};
  return {
    name: String(org.name || '').trim(),
    sector: String(org.sector || '').trim(),
    size: String(org.size || '').trim(),
    email: String(org.email || '').trim(),
  };
}

// POST /api/assess
const createAssessment = asyncHandler(async (req, res) => {
  const body = req.body || {};

  const organization = normalizeOrg(body.organization);
  const ghanaResponses = pickResponses(body, ['ghana_responses', 'ghana', 'ncf', 'ncf_responses']);
  const isoResponses = pickResponses(body, ['iso_responses', 'iso', 'iso27002_responses']);

  const ghanaFw = await getFramework('ghana');
  const isoFw = await getFramework('iso27002');
  if (!ghanaFw || !isoFw) {
    const err = new Error('Framework reference data unavailable');
    err.status = 503;
    throw err;
  }

  const ghanaScores = calculateScores(ghanaFw.groups, ghanaResponses);
  const isoScores = calculateScores(isoFw.groups, isoResponses);
  const recommendations = generateRecommendations(ghanaScores, isoScores);

  const doc = await Assessment.create({
    organization,
    date: new Date(),
    ghana_scores: ghanaScores,
    iso_scores: isoScores,
    recommendations,
    alignment_score: round1((ghanaScores.overall + isoScores.overall) / 2),
    ghana_maturity: getMaturityLabel(ghanaScores.overall),
    iso_maturity: getMaturityLabel(isoScores.overall),
    ghana_responses: responsesToArray(ghanaResponses),
    iso_responses: responsesToArray(isoResponses),
  });

  res.status(201).json(doc.toApi());
});

// GET /api/assessments
const listAssessments = asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const docs = await Assessment.find().sort({ date: -1 }).limit(limit);
  res.json(docs.map((d) => d.toSummary()));
});

// GET /api/assessments/:id
const getAssessment = asyncHandler(async (req, res) => {
  const doc = await Assessment.findOne({ assessmentId: req.params.id });
  if (!doc) return res.status(404).json({ error: 'Assessment not found' });
  res.json(doc.toApi());
});

// DELETE /api/assessments/:id
const deleteAssessment = asyncHandler(async (req, res) => {
  const doc = await Assessment.findOneAndDelete({ assessmentId: req.params.id });
  if (!doc) return res.status(404).json({ error: 'Assessment not found' });
  res.json({ deleted: true, id: req.params.id });
});

// POST /api/report  { assessment_id }
const getReport = asyncHandler(async (req, res) => {
  const aid = (req.body && req.body.assessment_id) || '';
  const doc = await Assessment.findOne({ assessmentId: aid });
  if (!doc) return res.status(404).json({ error: 'Assessment not found' });
  res.json(doc.toApi());
});

module.exports = {
  createAssessment,
  listAssessments,
  getAssessment,
  deleteAssessment,
  getReport,
};

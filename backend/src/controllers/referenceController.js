'use strict';

const Framework = require('../models/Framework');
const asyncHandler = require('../middleware/asyncHandler');
const { GHANA_REQUIREMENTS, ISO27002 } = require('../data/frameworks');
const { REQUIREMENT_LINKS, GAP_ANALYSIS } = require('../data/derived');

/** Serialize a framework document to the legacy API shape (domains/themes). */
function frameworkDocToApi(doc) {
  return {
    name: doc.name,
    version: doc.version,
    [doc.groupLabel]: doc.groups.map((g) => ({
      id: g.id,
      name: g.name,
      controls: g.controls.map((c) => ({
        id: c.id,
        title: c.title,
        ...(c.description ? { description: c.description } : {}),
        weight: c.weight,
        ...(c.tier ? { tier: c.tier, source: c.source } : {}),
      })),
    })),
  };
}

/** Static fallback in the legacy shape when the DB isn't seeded. */
function staticFrameworkApi(fw) {
  return {
    name: fw.name,
    version: fw.version,
    [fw.groupLabel]: (fw.domains || fw.themes).map((g) => ({
      id: g.id,
      name: g.name,
      controls: g.controls.map((c) => ({
        id: c.id,
        title: c.title,
        ...(c.description ? { description: c.description } : {}),
        weight: c.weight,
        ...(c.tier ? { tier: c.tier, source: c.source } : {}),
      })),
    })),
  };
}

// GET /api/frameworks/ghana
const getGhana = asyncHandler(async (req, res) => {
  const doc = await Framework.findOne({ key: 'ghana' }).lean();
  res.json(doc ? frameworkDocToApi(doc) : staticFrameworkApi(GHANA_REQUIREMENTS));
});

// GET /api/frameworks/iso27002
const getIso = asyncHandler(async (req, res) => {
  const doc = await Framework.findOne({ key: 'iso27002' }).lean();
  res.json(doc ? frameworkDocToApi(doc) : staticFrameworkApi(ISO27002));
});

// GET /api/frameworks  (list both, lightweight)
const listFrameworks = asyncHandler(async (req, res) => {
  const docs = await Framework.find().lean();
  const source = docs.length
    ? docs.map((d) => ({ key: d.key, name: d.name, version: d.version, groups: d.groups.length }))
    : [GHANA_REQUIREMENTS, ISO27002].map((f) => ({
        key: f.key,
        name: f.name,
        version: f.version,
        groups: (f.domains || f.themes).length,
      }));
  res.json(source);
});

// GET /api/mapping  (requirement -> ISO 27002 links; proposed, not yet validated)
const getMapping = asyncHandler(async (req, res) => {
  res.json(REQUIREMENT_LINKS);
});

// GET /api/gaps  (derived from the requirements dataset)
const getGaps = asyncHandler(async (req, res) => {
  res.json(GAP_ANALYSIS);
});

module.exports = { getGhana, getIso, listFrameworks, getMapping, getGaps };

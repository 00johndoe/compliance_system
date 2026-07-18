'use strict';

const Framework = require('../models/Framework');
const Mapping = require('../models/Mapping');
const GapAnalysis = require('../models/GapAnalysis');
const asyncHandler = require('../middleware/asyncHandler');
const { GHANA_NCF, ISO27002 } = require('../data/frameworks');
const { CONTROL_MAPPING } = require('../data/mapping');
const { GAP_ANALYSIS } = require('../data/gaps');

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
      })),
    })),
  };
}

// GET /api/frameworks/ghana
const getGhana = asyncHandler(async (req, res) => {
  const doc = await Framework.findOne({ key: 'ghana' }).lean();
  res.json(doc ? frameworkDocToApi(doc) : staticFrameworkApi(GHANA_NCF));
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
    : [GHANA_NCF, ISO27002].map((f) => ({
        key: f.key,
        name: f.name,
        version: f.version,
        groups: (f.domains || f.themes).length,
      }));
  res.json(source);
});

// GET /api/mapping
const getMapping = asyncHandler(async (req, res) => {
  const docs = await Mapping.find().sort({ _id: 1 }).lean();
  if (!docs.length) return res.json(CONTROL_MAPPING);
  res.json(docs.map((m) => ({ ncf: m.ncf, iso: m.iso, alignment: m.alignment, notes: m.notes })));
});

// GET /api/gaps
const getGaps = asyncHandler(async (req, res) => {
  const doc = await GapAnalysis.findOne({ key: 'default' });
  res.json(doc ? doc.toApi() : GAP_ANALYSIS);
});

module.exports = { getGhana, getIso, listFrameworks, getMapping, getGaps };

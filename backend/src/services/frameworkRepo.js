'use strict';

const Framework = require('../models/Framework');
const { GHANA_NCF, ISO27002 } = require('../data/frameworks');

/** Normalizes static framework data into { key, name, version, groupLabel, groups }. */
function staticToNormalized(fw) {
  return {
    key: fw.key,
    name: fw.name,
    version: fw.version,
    groupLabel: fw.groupLabel,
    groups: fw.domains || fw.themes || [],
  };
}

const STATIC = {
  ghana: staticToNormalized(GHANA_NCF),
  iso: staticToNormalized(ISO27002),
  iso27002: staticToNormalized(ISO27002),
};

/**
 * Load a framework's normalized groups. Prefers the DB; falls back to the
 * built-in static definition if the DB has not been seeded yet.
 *
 * @param {'ghana'|'iso'|'iso27002'} type
 */
async function getFramework(type) {
  const key = type === 'iso' ? 'iso27002' : type;
  const doc = await Framework.findOne({ key }).lean();
  if (doc) {
    return {
      key: doc.key,
      name: doc.name,
      version: doc.version,
      groupLabel: doc.groupLabel,
      groups: doc.groups,
    };
  }
  return STATIC[type] || STATIC[key] || null;
}

module.exports = { getFramework, staticToNormalized, STATIC };

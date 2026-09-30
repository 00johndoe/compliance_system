'use strict';

/**
 * Mapping and gap analysis derived from the requirements dataset, so they can
 * never drift from it. Links are PROPOSALS awaiting validation (no strength
 * ratings are given because none have been reviewed).
 */

const { REQUIREMENTS, ISO27002, flattenControls } = require('./frameworks');

const isoControls = flattenControls(ISO27002);
const isoById = new Map(isoControls.map((c) => [c.id, c]));

/** One row per (requirement, ISO control) link. */
const REQUIREMENT_LINKS = REQUIREMENTS.requirements.flatMap((r) =>
  r.iso27002Links.map((iso) => ({ requirement: r.id, iso, status: 'proposed' }))
);

function buildGapAnalysis() {
  const reqs = REQUIREMENTS.requirements;
  const linked = new Set(REQUIREMENT_LINKS.map((l) => l.iso));

  const ghana_unique = reqs
    .filter((r) => r.iso27002Links.length === 0)
    .map((r) => ({
      control: r.id,
      title: r.title,
      reason: 'No ISO/IEC 27002 control has been proposed for this requirement.',
    }));

  const iso_unique = isoControls
    .filter((c) => !linked.has(c.id))
    .map((c) => ({
      control: c.id,
      title: c.title,
      reason: 'Not referenced by any Ghana requirement in this dataset.',
    }));

  const coverage = ISO27002.themes.map((t) => ({
    theme: t.name,
    total: t.controls.length,
    linked: t.controls.filter((c) => linked.has(c.id)).length,
  }));

  const tierCount = (id) => reqs.filter((r) => r.tier === id).length;
  const structural_comparison = [
    {
      aspect: 'Structure',
      ghana: `${reqs.length} cited requirements in ${new Set(reqs.map((r) => r.group)).size} groups (Tier 1A: ${tierCount('1A')}, Tier 1B: ${tierCount('1B')}, Tier 2: ${tierCount('2')})`,
      iso: `${ISO27002.themes.length} themes, ${isoControls.length} controls`,
    },
    { aspect: 'Basis', ghana: 'Legal duties and CSA directives (paraphrased)', iso: 'International best-practice standard' },
    { aspect: 'Applicability', ghana: 'Depends on the organisation: all, personal-data processors, designated CII owners', iso: 'Selected by risk assessment' },
    { aspect: 'Legal context', ghana: 'Act 1038, Act 843, CSA CII Directive', iso: 'Framework-agnostic' },
    { aspect: 'Certification', ghana: 'Regulatory compliance, no certificate', iso: 'ISO/IEC 27001 certification uses this guidance' },
  ];

  return { ghana_unique, iso_unique, coverage, structural_comparison };
}

const GAP_ANALYSIS = buildGapAnalysis();

module.exports = { REQUIREMENT_LINKS, GAP_ANALYSIS, isoById };

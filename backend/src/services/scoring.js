'use strict';

/**
 * Compliance scoring engine.
 *
 * Simple (unweighted) average methodology. Each control is scored on a 0–5
 * maturity scale, converted to a 0–100% score, then averaged:
 *
 *     control_score   = (maturity / 5) × 100
 *     domain_score    = average(control_score) over the domain's controls
 *     overall_score   = average(control_score) over all controls
 *
 * Control `weight` is retained as criticality metadata (used to prioritise
 * recommendations) but no longer influences the compliance score itself.
 */

function round1(n) {
  return Math.round(n * 10) / 10;
}

function clampMaturity(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 5) return 5;
  return n;
}

/**
 * @param {Array<{id,name,controls:Array<{id,title,weight}>}>} groups
 * @param {Object|Map} responses  map of controlId -> maturity (0..5)
 * @returns {{overall:number, domains:Array}}
 */
function calculateScores(groups, responses) {
  const get = (id) => {
    if (responses instanceof Map) return responses.get(id);
    return responses ? responses[id] : undefined;
  };

  const domainScores = [];
  let totalScore = 0;
  let totalControls = 0;

  for (const group of groups) {
    let groupScoreSum = 0;
    const controlResults = [];

    for (const control of group.controls) {
      const maturity = clampMaturity(get(control.id) ?? 0);
      const score = (maturity / 5) * 100;

      groupScoreSum += score;
      totalScore += score;
      totalControls += 1;

      controlResults.push({
        id: control.id,
        title: control.title,
        maturity,
        score: round1(score),
        weight: control.weight,
      });
    }

    const count = group.controls.length;
    domainScores.push({
      id: group.id,
      name: group.name,
      score: count > 0 ? round1(groupScoreSum / count) : 0,
      controls: controlResults,
    });
  }

  const overall = totalControls > 0 ? round1(totalScore / totalControls) : 0;
  return { overall, domains: domainScores };
}

function getMaturityLabel(score) {
  if (score >= 90) return 'Optimized';
  if (score >= 70) return 'Managed';
  if (score >= 50) return 'Defined';
  if (score >= 30) return 'Developing';
  if (score >= 10) return 'Initial';
  return 'Non-Existent';
}

const PRIORITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

/**
 * Generate prioritized, actionable recommendations from computed scores.
 * Port of generate_recommendations() in server.py.
 */
function generateRecommendations(ghanaScores, isoScores) {
  const recs = [];
  const allControls = [];

  for (const d of ghanaScores.domains) {
    for (const c of d.controls) {
      allControls.push({ ...c, framework: 'Ghana NCF', domain: d.name });
    }
  }
  for (const d of isoScores.domains) {
    for (const c of d.controls) {
      allControls.push({ ...c, framework: 'ISO 27002', domain: d.name });
    }
  }

  for (const ctrl of allControls) {
    const label = `${ctrl.framework} - ${ctrl.id}`;
    if (ctrl.score < 40 && ctrl.weight >= 4) {
      recs.push({
        priority: 'Critical',
        control: label,
        title: ctrl.title,
        current_score: ctrl.score,
        target_score: 80,
        recommendation: `Urgently implement ${ctrl.title}. Current maturity is critically low for a high-weight control.`,
      });
    } else if (ctrl.score < 60 && ctrl.weight >= 4) {
      recs.push({
        priority: 'High',
        control: label,
        title: ctrl.title,
        current_score: ctrl.score,
        target_score: 80,
        recommendation: `Prioritize improvement of ${ctrl.title} to meet compliance targets.`,
      });
    } else if (ctrl.score < 60) {
      recs.push({
        priority: 'Medium',
        control: label,
        title: ctrl.title,
        current_score: ctrl.score,
        target_score: 70,
        recommendation: `Plan improvement of ${ctrl.title} in the next review cycle.`,
      });
    } else if (ctrl.score < 80) {
      recs.push({
        priority: 'Low',
        control: label,
        title: ctrl.title,
        current_score: ctrl.score,
        target_score: 90,
        recommendation: `Fine-tune ${ctrl.title} to achieve optimized maturity level.`,
      });
    }
  }

  recs.sort((a, b) => {
    const pa = PRIORITY_ORDER[a.priority] ?? 4;
    const pb = PRIORITY_ORDER[b.priority] ?? 4;
    if (pa !== pb) return pa - pb;
    return b.current_score - a.current_score;
  });

  return recs;
}

module.exports = {
  calculateScores,
  getMaturityLabel,
  generateRecommendations,
  round1,
  clampMaturity,
};

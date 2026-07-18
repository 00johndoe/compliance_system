'use strict';

const { body, param } = require('express-validator');
const { GHANA_NCF, ISO27002, flattenControls } = require('../data/frameworks');
const { SECTORS, SIZES } = require('../data/orgOptions');

const GHANA_IDS = new Set(flattenControls(GHANA_NCF).map((c) => c.id));
const ISO_IDS = new Set(flattenControls(ISO27002).map((c) => c.id));

/**
 * Builds a custom validator for a responses object: `{ controlId: maturity }`.
 * Ensures it is a plain object, every key is a known control id, and every
 * value is a number in the 0–5 maturity range.
 */
function responsesValidator(validIds, label) {
  return (value) => {
    if (value === undefined || value === null) return true; // optional
    if (typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`${label} must be an object of { controlId: maturity }`);
    }
    for (const [key, raw] of Object.entries(value)) {
      if (!validIds.has(key)) {
        throw new Error(`${label}: unknown control id "${key}"`);
      }
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 0 || n > 5) {
        throw new Error(`${label}: maturity for "${key}" must be a number between 0 and 5`);
      }
    }
    return true;
  };
}

// POST /api/assess
const createAssessmentRules = [
  body('organization')
    .optional()
    .isObject()
    .withMessage('organization must be an object'),

  body('organization.name')
    .exists({ checkFalsy: true })
    .withMessage('organization name is required')
    .bail()
    .isString()
    .withMessage('organization name must be text')
    .bail()
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('organization name must be 2–200 characters')
    .matches(/^[\p{L}\p{N}\s.,'&()\-/]+$/u)
    .withMessage('organization name contains invalid characters'),

  body('organization.email')
    .exists({ checkFalsy: true })
    .withMessage('contact email is required')
    .bail()
    .isEmail()
    .withMessage('a valid email address is required')
    .normalizeEmail(),

  body('organization.sector')
    .exists({ checkFalsy: true })
    .withMessage('sector is required')
    .bail()
    .isIn(SECTORS)
    .withMessage(`sector must be one of: ${SECTORS.join(', ')}`),

  body('organization.size')
    .exists({ checkFalsy: true })
    .withMessage('organization size is required')
    .bail()
    .isIn(SIZES)
    .withMessage(`organization size must be one of: ${SIZES.join(', ')}`),

  body('ghana_responses').custom(responsesValidator(GHANA_IDS, 'ghana_responses')),
  body('ghana').custom(responsesValidator(GHANA_IDS, 'ghana')),
  body('ncf').custom(responsesValidator(GHANA_IDS, 'ncf')),
  body('iso_responses').custom(responsesValidator(ISO_IDS, 'iso_responses')),
  body('iso').custom(responsesValidator(ISO_IDS, 'iso')),
];

// POST /api/report
const reportRules = [
  body('assessment_id')
    .exists({ checkFalsy: true })
    .withMessage('assessment_id is required')
    .bail()
    .isString()
    .withMessage('assessment_id must be a string')
    .trim()
    .matches(/^[a-zA-Z0-9-]{1,64}$/)
    .withMessage('assessment_id has an invalid format'),
];

// GET/DELETE /api/assessments/:id
const idParamRules = [
  param('id')
    .isString()
    .withMessage('id must be a string')
    .trim()
    .matches(/^[a-zA-Z0-9-]{1,64}$/)
    .withMessage('assessment id has an invalid format'),
];

module.exports = { createAssessmentRules, reportRules, idParamRules };
